#include "dvaas/test_vector_stats.h"

#include <iostream>

#include "dvaas/test_vector.pb.h"
#include "gtest/gtest.h"
#include "gutil/testing.h"

namespace dvaas {
namespace {

PacketTestOutcomes GetPacketTestOutcomes() {
  return gutil::ParseProtoOrDie<PacketTestOutcomes>(R"pb(
    # Correct drop.
    outcomes {
      test_run {
        test_vector {
          input {}
          # Deterministic drop.
          acceptable_outputs {
            packets: []
            packet_ins: []
          }
        }
        actual_output {
          packets: []
          packet_ins: []
        }
      }
      # Passed.
      test_result {}
    }

    # Incorrect forward.
    outcomes {
      test_run {
        test_vector {
          input {}
          # Deterministic forward.
          acceptable_outputs {
            packets {}
            packet_ins: []
          }
        }
        actual_output {
          packets {}
          packet_ins: []
        }
      }
      # Failed.
      test_result {
        failure { minimization_analysis { reproducibility_rate: 0.0 } }
      }
    }

    # Correct forward.
    outcomes {
      test_run {
        test_vector {
          input {}
          # Deterministic forward.
          acceptable_outputs {
            packets {}
            packet_ins: []
          }
        }
        actual_output {
          packets {}
          packet_ins: []
        }
      }
      # Passed.
      test_result {}
    }

    # Correct multi forward.
    outcomes {
      test_run {
        test_vector {
          input {}
          # Deterministic multi forward.
          acceptable_outputs {
            packets {}
            packets {}
            packets {}
            packet_ins: []
          }
        }
        actual_output {
          packets {}
          packets {}
          packets {}
          packet_ins: []
        }
      }
      # Passed.
      test_result {}
    }

    # Incorrect punt.
    outcomes {
      test_run {
        test_vector {
          input {}
          # Deterministic trap.
          acceptable_outputs {
            packets: []
            packet_ins {}
          }
        }
        actual_output {
          packets: []
          packet_ins: {}
        }
      }
      # Failed.
      test_result {
        failure { minimization_analysis { reproducibility_rate: 0.0 } }
      }
    }

    # Incorrect punt with no reproducibility rate.
    outcomes {
      test_run {
        test_vector {
          input {}
          # Deterministic trap.
          acceptable_outputs {
            packets: []
            packet_ins {}
          }
        }
        actual_output {
          packets: []
          packet_ins: {}
        }
      }
      # Failed.
      test_result { failure {} }
    }

    # Correct forward & copy.
    outcomes {
      test_run {
        test_vector {
          input {}
          # Deterministic forward & copy.
          acceptable_outputs {
            packets {}
            packet_ins {}
          }
        }
        actual_output {
          packets {}
          packet_ins: {}
        }
      }
      # Passed.
      test_result {
          # No reproducibility rate is given.
      }
    }
  )pb");
}

TEST(TestVectorStatsGoldenTest,
     ComputeTestVectorStatsAndExplainTestVectorStats) {
  PacketTestOutcomes outcomes = GetPacketTestOutcomes();
  TestVectorStats stats = ComputeTestVectorStats(outcomes);
  std::cout << ExplainTestVectorStats(stats);
}

TEST(TestVectorStatsGoldenTest, ReproducibilityRateScenarios) {
  PacketTestOutcomes outcomes = GetPacketTestOutcomes();
  outcomes.mutable_outcomes(1)
      ->mutable_test_result()
      ->mutable_failure()
      ->mutable_minimization_analysis()
      ->set_reproducibility_rate(1.0);
  outcomes.mutable_outcomes(4)
      ->mutable_test_result()
      ->mutable_failure()
      ->mutable_minimization_analysis()
      ->set_reproducibility_rate(1.0);
  TestVectorStats stats = ComputeTestVectorStats(outcomes);
  std::cout << ExplainTestVectorStats(stats);

  outcomes.mutable_outcomes(4)
      ->mutable_test_result()
      ->mutable_failure()
      ->mutable_minimization_analysis()
      ->set_reproducibility_rate(0.0);
  stats = ComputeTestVectorStats(outcomes);
  std::cout << ExplainTestVectorStats(stats);
}

}  // namespace
}  // namespace dvaas
