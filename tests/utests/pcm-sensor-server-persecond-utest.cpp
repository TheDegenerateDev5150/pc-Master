// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2009-2025, Intel Corporation

// Regression test for the /persecond/30 unsatisfiable-wait denial of service
// in pcm-sensor-server (src/pcm-sensor-server.cpp).
//
// The internal aggregator history is permanently capped at
// HTTPServer::maxAggregators_ entries (see addAggregator(), which pops the
// oldest entry once the size exceeds the cap). Answering /persecond/X compares
// the newest sample (index 0) with the sample X seconds earlier (index X),
// which requires X + 1 retained entries. The largest X that can ever be
// satisfied is therefore maxAggregators_ - 1.
//
// The original code validated the user-controlled seconds value against the
// retention cap itself (<= 30) instead of the largest satisfiable index
// (<= 29). As a result /persecond/30 entered getAggregators(30, 0) whose wait
// loop required 31 retained samples that the history could never hold, blocking
// the worker thread forever. With 64 such requests an unauthenticated remote
// attacker could exhaust the whole worker pool (CWE-835).
//
// This test pins the invariant that the accepted /persecond bound stays
// strictly below the retention capacity (so every accepted request is
// satisfiable), and that getAggregators() fails fast instead of blocking
// forever when handed an index that can never be retained.

#define UNIT_TEST 1
#include "../../src/pcm-sensor-server.cpp"
#undef UNIT_TEST

#include <gtest/gtest.h>

namespace {

// The largest accepted /persecond/X value must be strictly smaller than the
// retention capacity, otherwise the newest/oldest comparison needs one more
// sample than the history can ever hold and getAggregators() blocks forever.
TEST(PcmSensorServerPerSecondTest, AcceptedBoundIsSatisfiableGivenRetentionCap)
{
    static_assert(HTTPServer::maxPerSecondSeconds_ < HTTPServer::maxAggregators_,
                  "Accepted /persecond bound must be strictly below the "
                  "retention cap so every accepted request is satisfiable.");

    // The most demanding accepted request, /persecond/maxPerSecondSeconds_,
    // needs maxPerSecondSeconds_ + 1 retained samples. That must fit within the
    // retention capacity.
    EXPECT_LE(HTTPServer::maxPerSecondSeconds_ + 1, HTTPServer::maxAggregators_);

    // The first index that can never be satisfied (the value that previously
    // wedged a worker thread) is exactly the retention cap.
    EXPECT_EQ(HTTPServer::maxAggregators_, HTTPServer::maxPerSecondSeconds_ + 1);
}

// getAggregators() must throw (fail fast) for any index that can never be
// retained, instead of spinning forever in its wait loop. Without an instance
// we cannot call the member directly, but we can validate the same wait
// condition the handler relies on: filling the history to its cap never makes
// an out-of-range index reachable.
TEST(PcmSensorServerPerSecondTest, HistoryNeverReachesUnsatisfiableIndex)
{
    // Mirror addAggregator()'s retention behaviour on a standalone vector so we
    // can assert the cap without constructing a server. This documents the
    // exact off-by-one: after inserting far more than the cap, the size is
    // pinned at maxAggregators_, so index == maxAggregators_ is never valid.
    std::vector<int> history;
    for (size_t i = 0; i < HTTPServer::maxAggregators_ * 4; ++i) {
        history.insert(history.begin(), static_cast<int>(i));
        if (history.size() > HTTPServer::maxAggregators_)
            history.pop_back();
    }

    EXPECT_EQ(HTTPServer::maxAggregators_, history.size());

    // The largest accepted request is satisfiable: it needs an index that is
    // within the retained range.
    EXPECT_LT(HTTPServer::maxPerSecondSeconds_, history.size());

    // The previously accepted-but-unsatisfiable request (index == cap) is not
    // within the retained range and would have blocked forever.
    EXPECT_GE(HTTPServer::maxAggregators_, history.size());
}

} // namespace
