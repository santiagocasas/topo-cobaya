from flaky import flaky
import numpy as np
import pytest
import time

from cobaya.likelihoods.gaussian_mixture import random_cov
from cobaya.tools import KL_norm
from cobaya.likelihood import Likelihood
from cobaya.run import run
from cobaya import mpi
from cobaya.yaml import yaml_load
from .common_sampler import body_of_test, body_of_test_speeds

pytestmark = pytest.mark.mpi

# Max number of tries per test
max_runs = 3


@flaky(max_runs=max_runs, min_passes=1)
def test_mcmc(tmpdir, packages_path=None):
    dimension = 3
    # Random initial proposal
    cov = mpi.share(
        random_cov(dimension * [[0, 1]], O_std_min=0.01, O_std_max=0.5)
        if mpi.is_main_process() else None)
    info_sampler = {"mcmc": {
        # Bad guess for covmat, so big burn in and max_tries
        "max_tries": 3000, "burn_in": 100 * dimension,
        # Learn proposal
        # "learn_proposal": True,  # default now!
        # Proposal
        "covmat": cov}}

    def check_gaussian(sampler_instance):
        KL_proposer = KL_norm(
            S1=sampler_instance.model.likelihood["gaussian_mixture"].covs[0],
            S2=sampler_instance.proposer.get_covariance())
        KL_sample = KL_norm(
            m1=sampler_instance.model.likelihood["gaussian_mixture"].means[0],
            S1=sampler_instance.model.likelihood["gaussian_mixture"].covs[0],
            m2=sampler_instance.collection.mean(
                first=int(sampler_instance.n() / 2)),
            S2=sampler_instance.collection.cov(
                first=int(sampler_instance.n() / 2)))
        print("KL proposer: %g ; KL sample: %g" % (KL_proposer, KL_sample))

    if mpi.rank() == 0:
        info_sampler["mcmc"].update({
            # Callback to check KL divergence -- disabled in the automatic test
            "callback_function": check_gaussian, "callback_every": 100})
    body_of_test(dimension=dimension, info_sampler=info_sampler, tmpdir=tmpdir)


yaml_drag = r"""
params:
  a:
    prior:
      min: -0.5
      max: 3
    proposal: 0.2
  b:
    prior:
      dist: norm
      loc: 0
      scale: 1
    ref: 0
    proposal: 0.5
sampler:
  mcmc:
   drag: True
   measure_speeds: False
   Rminus1_stop: 0.001   
   Rminus1_cl_stop: 0.04
"""


class GaussLike(Likelihood):
    speed = 100
    params = {'a': None}

    def calculate(self, state, want_derived=True, **params_values_dict):
        state["logp"] = - (params_values_dict['a'] - 0.2) ** 2 / 0.15 / 2


class GaussLike2(Likelihood):
    speed = 600
    params = {'a': None, 'b': None}

    def calculate(self, state, want_derived=True, **params_values_dict):
        state["logp"] = - ((params_values_dict['a'] - 0.2) ** 2 +
                           params_values_dict['b'] ** 2) / 0.2 / 2


@flaky(max_runs=max_runs, min_passes=1)
@mpi.sync_errors
def test_mcmc_drag_results():
    info = yaml_load(yaml_drag)
    info['likelihood'] = {'g1': {'external': GaussLike}, 'g2': {'external': GaussLike2}}
    updated_info, sampler = run(info)
    products = sampler.products()
    from getdist.mcsamples import MCSamplesFromCobaya
    products["sample"] = mpi.allgather(products["sample"])
    gdample = MCSamplesFromCobaya(updated_info, products["sample"], ignore_rows=0.2)
    assert abs(gdample.mean('a') - 0.2) < 0.02
    assert abs(gdample.mean('b')) < 0.02
    assert abs(gdample.std('a') - 0.293) < 0.03
    assert abs(gdample.std('b') - 0.4) < 0.03


yaml = r"""
likelihood:
  gaussian_mixture:
    means: [0.2, 0]
    covs: [[0.1, 0.05], [0.05,0.2]]

params:
  a:
    prior:
      min: -0.5
      max: 3
    latex: \alpha
  b:
    prior:
      dist: norm
      loc: 0
      scale: 1
    ref: 0
    proposal: 0.5
    latex: \beta
sampler:
  mcmc:
    """


@pytest.mark.mpionly
def test_mcmc_sync():
    info = yaml_load(yaml)
    print('Test end synchronization')

    if mpi.rank() == 1:
        max_samples = 200
    else:
        max_samples = 600
    # simulate asynchronous ending sampling loop
    info['sampler']['mcmc'] = {'max_samples': max_samples}

    updated_info, sampler = run(info)
    assert len(sampler.products()["sample"]) == max_samples

    print('Test error synchronization')
    if mpi.rank() == 0:
        info['sampler']['mcmc'] = {'max_samples': 'none'}
        with pytest.raises(TypeError):
            run(info)
    else:
        with pytest.raises(mpi.OtherProcessError):
            run(info)

    aborted = False

    def test_abort():
        nonlocal aborted
        aborted = True

    # test error converted into MPI_ABORT after timeout
    # noinspection PyTypeChecker
    with pytest.raises((ValueError, mpi.OtherProcessError)):
        with mpi.ProcessState('test', time_out_seconds=0.5,
                              timeout_abort_proc=test_abort):
            if mpi.rank() != 1:
                time.sleep(0.6)  # fake hang
            else:
                raise ValueError('errored')
    if mpi.rank() == 1:
        assert aborted


@flaky(max_runs=max_runs, min_passes=1)
def test_mcmc_blocking():
    info_mcmc = {"mcmc": {"burn_in": 0, "learn_proposal": False}}
    body_of_test_speeds(info_mcmc)


@flaky(max_runs=max_runs, min_passes=1)
def test_mcmc_oversampling():
    info_mcmc = {"mcmc": {"burn_in": 0, "learn_proposal": False, "oversample_power": 1}}
    body_of_test_speeds(info_mcmc)


@flaky(max_runs=max_runs, min_passes=1)
def test_mcmc_oversampling_manual():
    # TODO - update ('oversample')
    info_mcmc = {"mcmc": {"burn_in": 0, "learn_proposal": False, "oversample": True}}
    body_of_test_speeds(info_mcmc, manual_blocking=True)


# The flaky test fails if likes or derived at chain points are not reproduced directly
# (dragging is somewhat delicate)
@flaky(max_runs=max_runs, min_passes=1,
       rerun_filter=(lambda err, *args: issubclass(err[0], AssertionError)))
def test_mcmc_dragging():
    info_mcmc = {"mcmc": {"burn_in": 0, "learn_proposal": False,
                          "drag": True, "oversample_power": 1}}
    body_of_test_speeds(info_mcmc)


def _make_gaussian_like(nparam):
    class LikeTest(Likelihood):
        params = {'x' + str(name): {'prior': {'min': -5, 'max': 5}, 'proposal': 1}
                  for name in range(nparam)}

        def calculate(self, state, want_derived=True, **params_values_dict):
            state["logp"] = -np.sum(np.array(list(params_values_dict.values())) ** 2 / 2)

    return LikeTest


def _test_overhead_timing(dim=15):
    # prints timing for simple Gaussian vanilla mcmc
    import pstats
    from cProfile import Profile
    from io import StringIO
    # noinspection PyUnresolvedReferences
    from cobaya.samplers.mcmc import proposal  # one-time numba compile out of profiling

    LikeTest = _make_gaussian_like(dim)
    info = {'likelihood': {'like': LikeTest}, 'debug': False, 'sampler': {
        'mcmc': {'max_samples': 1000, 'burn_in': 0, "learn_proposal": False,
                 "Rminus1_stop": 0.0001}}}
    prof = Profile()
    prof.enable()
    run(info)
    prof.disable()
    # prof.dump_stats("out.prof")  # to visualize with e.g. snakeviz
    s = StringIO()
    ps = pstats.Stats(prof, stream=s)
    print_n_calls = 10
    ps.strip_dirs()
    ps.sort_stats('time')
    ps.print_stats(print_n_calls)
    ps.sort_stats('cumtime')
    ps.print_stats(print_n_calls)
    print(s.getvalue())
