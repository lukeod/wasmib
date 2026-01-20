//! Resolver tracing support (feature-gated).
//!
//! Provides structured trace events for debugging resolution issues.
//! Zero overhead when the `tracing` feature is disabled.

use crate::model::{ModuleId, NodeId};

/// Trace verbosity level.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum TraceLevel {
    /// Critical errors only.
    Error,
    /// Warnings and errors.
    Warn,
    /// Informational messages (phase boundaries, summary stats).
    Info,
    /// Detailed debugging (individual lookups, decisions).
    Debug,
    /// Verbose tracing (every operation).
    Trace,
}

/// Resolution phase identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// Phase 1: Module registration.
    Registration,
    /// Phase 2: Import resolution.
    Imports,
    /// Phase 3: Type resolution.
    Types,
    /// Phase 4: OID resolution.
    Oids,
    /// Phase 5: Semantic analysis.
    Semantics,
}

impl core::fmt::Display for Phase {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Phase::Registration => write!(f, "registration"),
            Phase::Imports => write!(f, "imports"),
            Phase::Types => write!(f, "types"),
            Phase::Oids => write!(f, "oids"),
            Phase::Semantics => write!(f, "semantics"),
        }
    }
}

/// Structured trace events emitted during resolution.
#[derive(Clone, Debug)]
pub enum TraceEvent<'a> {
    /// A resolution phase is starting.
    PhaseStart { phase: Phase },
    /// A resolution phase has ended.
    PhaseEnd { phase: Phase },

    // === Import events ===
    /// A candidate module was scored for import resolution.
    ImportCandidateScored {
        /// The module name being imported from (e.g., "FOO-MIB").
        from_module: &'a str,
        /// The ModuleId of the candidate being scored.
        candidate_id: ModuleId,
        /// Number of requested symbols found in this candidate.
        symbols_found: usize,
        /// Total number of symbols being imported from this source.
        total: usize,
    },
    /// A candidate was chosen for all imports from a source module.
    ImportCandidateChosen {
        /// The module name being imported from.
        from_module: &'a str,
        /// The ModuleId that was chosen.
        chosen_id: ModuleId,
    },
    /// An import could not be resolved.
    ImportUnresolved {
        /// The ModuleId of the importing module.
        importing_module: ModuleId,
        /// The module name being imported from.
        from_module: &'a str,
        /// The symbol that couldn't be resolved.
        symbol: &'a str,
    },

    // === OID events ===
    /// An OID resolution pass is starting.
    OidPassStart {
        /// The pass number (0-indexed).
        pass: usize,
        /// Number of definitions pending resolution.
        pending: usize,
    },
    /// An OID resolution pass has ended.
    OidPassEnd {
        /// The pass number (0-indexed).
        pass: usize,
        /// Number of definitions resolved in this pass.
        resolved: usize,
        /// Number of definitions still pending.
        remaining: usize,
    },
    /// A symbol lookup occurred during OID resolution.
    OidLookup {
        /// The module performing the lookup.
        module_id: ModuleId,
        /// The definition being resolved.
        def_name: &'a str,
        /// The symbol being looked up.
        component: &'a str,
        /// Whether the lookup succeeded.
        found: bool,
    },
    /// An OID was successfully resolved.
    OidResolved {
        /// The definition name.
        def_name: &'a str,
        /// The resolved OID as a dotted string.
        oid: &'a str,
        /// The NodeId assigned.
        node_id: NodeId,
    },
    /// An OID could not be resolved.
    OidUnresolved {
        /// The definition name.
        def_name: &'a str,
        /// The unresolved component name.
        component: &'a str,
    },
}

/// Trait for receiving trace events during resolution.
///
/// Implement this trait to capture resolution diagnostics.
/// The tracer can filter events by returning a minimum trace level
/// from `level()`.
pub trait Tracer {
    /// Returns the minimum trace level to emit.
    ///
    /// Events below this level will not be passed to `trace()`.
    /// Default: `TraceLevel::Info`.
    fn level(&self) -> TraceLevel {
        TraceLevel::Info
    }

    /// Called for each trace event at or above the configured level.
    fn trace(&mut self, level: TraceLevel, event: TraceEvent<'_>);
}

/// A no-op tracer that discards all events.
///
/// Used as the default when tracing is not needed.
#[derive(Default, Clone, Copy, Debug)]
pub struct NoopTracer;

impl Tracer for NoopTracer {
    fn level(&self) -> TraceLevel {
        // Return the highest level to effectively disable all tracing
        TraceLevel::Error
    }

    fn trace(&mut self, _level: TraceLevel, _event: TraceEvent<'_>) {
        // Intentionally empty
    }
}

/// Emit a trace event if the tracer level permits.
///
/// This macro checks the tracer's level before constructing the event,
/// enabling zero-cost tracing when the level is too low.
/// Events are only emitted if their level is at or below the tracer's level.
#[macro_export]
macro_rules! trace_event {
    ($tracer:expr, $level:expr, $event:expr) => {
        if $level <= $tracer.level() {
            $tracer.trace($level, $event);
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    struct TestTracer {
        events: Vec<(TraceLevel, String)>,
        min_level: TraceLevel,
    }

    impl TestTracer {
        fn new(level: TraceLevel) -> Self {
            Self {
                events: Vec::new(),
                min_level: level,
            }
        }
    }

    impl Tracer for TestTracer {
        fn level(&self) -> TraceLevel {
            self.min_level
        }

        fn trace(&mut self, level: TraceLevel, event: TraceEvent<'_>) {
            self.events.push((level, format!("{:?}", event)));
        }
    }

    #[test]
    fn test_noop_tracer() {
        let mut tracer = NoopTracer;
        tracer.trace(TraceLevel::Info, TraceEvent::PhaseStart { phase: Phase::Oids });
        // Should not panic
    }

    #[test]
    fn test_trace_level_ordering() {
        assert!(TraceLevel::Error < TraceLevel::Warn);
        assert!(TraceLevel::Warn < TraceLevel::Info);
        assert!(TraceLevel::Info < TraceLevel::Debug);
        assert!(TraceLevel::Debug < TraceLevel::Trace);
    }

    #[test]
    fn test_tracer_collects_events() {
        let mut tracer = TestTracer::new(TraceLevel::Info);
        tracer.trace(TraceLevel::Info, TraceEvent::PhaseStart { phase: Phase::Oids });
        tracer.trace(TraceLevel::Info, TraceEvent::PhaseEnd { phase: Phase::Oids });
        assert_eq!(tracer.events.len(), 2);
    }

    #[test]
    fn test_trace_event_macro() {
        let mut tracer = TestTracer::new(TraceLevel::Info);

        // This should be captured
        trace_event!(tracer, TraceLevel::Info, TraceEvent::PhaseStart { phase: Phase::Oids });
        assert_eq!(tracer.events.len(), 1);

        // This should not be captured (below level)
        trace_event!(tracer, TraceLevel::Debug, TraceEvent::PhaseEnd { phase: Phase::Oids });
        assert_eq!(tracer.events.len(), 1);
    }
}
