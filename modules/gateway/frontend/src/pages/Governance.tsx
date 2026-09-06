/**
 * Governance page — the admin tab for the governed-tool registry.
 *
 * Sub-tabs:
 *   Registry     — read-only catalogue of governed tools (filter + detail).
 *   Review queue — PENDING tools with Approve / Reject actions (sign-off).
 *   Audit trail  — placeholder (wired in a later step from CloudWatch decisions).
 *
 * Honest boundary shown to the reviewer: this registry is a review/catalogue
 * record. Cedar in the governance gateway is what actually gates tool access.
 * Approving a tool only turns it on if the governance module's
 * require_approval_to_enable is set — otherwise Cedar already fences by tenant.
 *
 * Mirrors the data-fetching + table + modal patterns in pages/AgentActivity.tsx.
 */

import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Alert,
  Badge,
  Button,
  Modal,
  Select,
  Table,
  Tabs,
  TabsList,
  Tab,
  TabPanel,
  type Column,
} from '@/components/ui';
import {
  approveGovernanceTool,
  getGovernanceConfig,
  listGovernanceDecisions,
  listGovernanceTools,
  rejectGovernanceTool,
} from '@/services/governance';
import type {
  DecisionOutcome,
  GovernanceDecision,
  GovernanceTool,
  GovernanceToolStatus,
} from '@/types/governance';

const PAGE_SIZE = 20;

const STATUS_OPTIONS = [
  { value: '', label: 'All statuses' },
  { value: 'PENDING', label: 'Pending' },
  { value: 'APPROVED', label: 'Approved' },
  { value: 'REJECTED', label: 'Rejected' },
];

function statusVariant(
  status: GovernanceToolStatus,
): 'success' | 'warning' | 'danger' | 'default' {
  switch (status) {
    case 'APPROVED':
      return 'success';
    case 'PENDING':
      return 'warning';
    case 'REJECTED':
      return 'danger';
    default:
      return 'default';
  }
}

function errorMessage(e: unknown): string {
  return (e as { message?: string })?.message || 'Something went wrong.';
}

// ---------------------------------------------------------------------------
// Registry tab — read-only catalogue
// ---------------------------------------------------------------------------

function RegistryTab() {
  const [tenant, setTenant] = useState('');
  const [status, setStatus] = useState('');
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<GovernanceTool | null>(null);

  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey: ['governance-tools', { tenant, status, page }],
    queryFn: () =>
      listGovernanceTools({
        tenant: tenant || undefined,
        status: (status as GovernanceToolStatus) || undefined,
        page,
        page_size: PAGE_SIZE,
      }),
  });

  const columns: Column<GovernanceTool>[] = [
    { key: 'name', header: 'Tool' },
    { key: 'tenant', header: 'Tenant' },
    { key: 'owner', header: 'Owner', render: (t) => t.owner || '—' },
    {
      key: 'status',
      header: 'Status',
      render: (t) => <Badge variant={statusVariant(t.status)}>{t.status}</Badge>,
    },
    {
      key: 'created_at',
      header: 'Registered',
      render: (t) =>
        t.created_at ? new Date(t.created_at).toLocaleDateString() : '—',
    },
  ];

  const total = data?.total ?? 0;
  const hasMore = data?.has_more ?? false;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-end gap-3">
        <div className="w-56">
          <Select
            label="Tenant"
            name="tenant"
            options={[{ value: '', label: 'All tenants' }]}
            placeholder="Filter by tenant (org_id)"
            value={tenant}
            onChange={(e) => {
              setTenant(e.target.value);
              setPage(1);
            }}
          />
        </div>
        <div className="w-48">
          <Select
            label="Status"
            name="status"
            options={STATUS_OPTIONS}
            value={status}
            onChange={(e) => {
              setStatus(e.target.value);
              setPage(1);
            }}
          />
        </div>
        <div className="ml-auto text-sm text-gray-500 dark:text-gray-400">
          {total} tool{total === 1 ? '' : 's'}
        </div>
      </div>

      {isError && (
        <Alert variant="error">
          {errorMessage(error)}{' '}
          <button className="underline" onClick={() => refetch()}>
            Retry
          </button>
        </Alert>
      )}

      <Table<GovernanceTool>
        columns={columns}
        data={data?.items ?? []}
        keyExtractor={(t) => t.id}
        onRowClick={(t) => setSelected(t)}
        isLoading={isLoading}
        emptyMessage="No governed tools found. Run a registry sync to import tools from governance.yaml."
      />

      {(page > 1 || hasMore) && (
        <div className="flex items-center justify-between">
          <Button
            variant="secondary"
            disabled={page <= 1}
            onClick={() => setPage((p) => Math.max(1, p - 1))}
          >
            Previous
          </Button>
          <span className="text-sm text-gray-500 dark:text-gray-400">Page {page}</span>
          <Button
            variant="secondary"
            disabled={!hasMore}
            onClick={() => setPage((p) => p + 1)}
          >
            Next
          </Button>
        </div>
      )}

      <ToolDetailModal tool={selected} onClose={() => setSelected(null)} />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Review queue tab — PENDING tools with approve/reject
// ---------------------------------------------------------------------------

function ReviewTab() {
  const queryClient = useQueryClient();
  const [rejecting, setRejecting] = useState<GovernanceTool | null>(null);
  const [rejectReason, setRejectReason] = useState('');
  const [actionError, setActionError] = useState<string | null>(null);

  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey: ['governance-tools', { status: 'PENDING', page: 1, review: true }],
    queryFn: () => listGovernanceTools({ status: 'PENDING', page: 1, page_size: 100 }),
  });

  const { data: config } = useQuery({
    queryKey: ['governance-config'],
    queryFn: getGovernanceConfig,
  });

  const invalidate = () => {
    // Refresh every governance-tools query (registry + review).
    queryClient.invalidateQueries({ queryKey: ['governance-tools'] });
  };

  const approveMut = useMutation({
    mutationFn: (id: string) => approveGovernanceTool(id),
    onSuccess: invalidate,
    onError: (e) => setActionError(errorMessage(e)),
  });

  const rejectMut = useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) =>
      rejectGovernanceTool(id, reason),
    onSuccess: () => {
      setRejecting(null);
      setRejectReason('');
      invalidate();
    },
    onError: (e) => setActionError(errorMessage(e)),
  });

  const busyId =
    approveMut.isPending
      ? (approveMut.variables as string | undefined)
      : undefined;

  const columns: Column<GovernanceTool>[] = [
    { key: 'name', header: 'Tool' },
    { key: 'tenant', header: 'Tenant' },
    { key: 'owner', header: 'Owner', render: (t) => t.owner || '—' },
    {
      key: 'actions',
      header: 'Actions',
      align: 'right',
      render: (t) => (
        <div className="flex justify-end gap-2">
          <Button
            size="sm"
            variant="primary"
            isLoading={busyId === t.id}
            onClick={() => {
              setActionError(null);
              approveMut.mutate(t.id);
            }}
          >
            Approve
          </Button>
          <Button
            size="sm"
            variant="danger"
            onClick={() => {
              setActionError(null);
              setRejectReason('');
              setRejecting(t);
            }}
          >
            Reject
          </Button>
        </div>
      ),
    },
  ];

  return (
    <div className="space-y-4">
      <p className="text-sm text-gray-500 dark:text-gray-400">
        Tools awaiting review.{' '}
        {config?.approval_enables_tool
          ? 'Approval generates the tool’s Cedar policy — approving genuinely turns the tool on.'
          : 'Approval is a sign-off record only. Cedar already fences tools by tenant, so approving does not by itself enable a tool.'}
      </p>

      {isError && (
        <Alert variant="error">
          {errorMessage(error)}{' '}
          <button className="underline" onClick={() => refetch()}>
            Retry
          </button>
        </Alert>
      )}
      {actionError && <Alert variant="error">{actionError}</Alert>}

      <Table<GovernanceTool>
        columns={columns}
        data={data?.items ?? []}
        keyExtractor={(t) => t.id}
        isLoading={isLoading}
        emptyMessage="Nothing to review — no tools are pending."
      />

      {/* Reject reason modal */}
      <Modal
        isOpen={rejecting !== null}
        onClose={() => setRejecting(null)}
        title={`Reject ${rejecting?.name ?? ''}`}
        size="md"
      >
        <div className="space-y-4">
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
            Reason (optional)
            <textarea
              className="mt-1 w-full px-3 py-2 border rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-white border-gray-300 dark:border-gray-600 focus:outline-none focus:ring-2 focus:ring-primary-500"
              rows={3}
              value={rejectReason}
              onChange={(e) => setRejectReason(e.target.value)}
              placeholder="Why is this tool being rejected?"
            />
          </label>
          <div className="flex justify-end gap-2">
            <Button variant="secondary" onClick={() => setRejecting(null)}>
              Cancel
            </Button>
            <Button
              variant="danger"
              isLoading={rejectMut.isPending}
              onClick={() =>
                rejecting &&
                rejectMut.mutate({ id: rejecting.id, reason: rejectReason })
              }
            >
              Reject tool
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Audit trail tab — policy decisions from the AgentCore decision log
// ---------------------------------------------------------------------------

const DECISION_OPTIONS = [
  { value: '', label: 'All decisions' },
  { value: 'ALLOW', label: 'Allowed' },
  { value: 'DENY', label: 'Denied' },
];

const WINDOW_OPTIONS = [
  { value: '1', label: 'Last 1 hour' },
  { value: '24', label: 'Last 24 hours' },
  { value: '168', label: 'Last 7 days' },
];

function AuditTab() {
  const [decision, setDecision] = useState('');
  const [tenant, setTenant] = useState('');
  const [windowHours, setWindowHours] = useState('24');

  const sinceMs = Date.now() - Number(windowHours) * 60 * 60 * 1000;

  const { data, isLoading, isError, error, refetch, isFetching } = useQuery({
    queryKey: ['governance-decisions', { decision, tenant, windowHours }],
    queryFn: () =>
      listGovernanceDecisions({
        decision: (decision as DecisionOutcome) || undefined,
        tenant: tenant || undefined,
        since_ms: Math.floor(sinceMs),
      }),
  });

  const columns: Column<GovernanceDecision>[] = [
    {
      key: 'ts',
      header: 'Time',
      render: (d) => (d.ts ? new Date(d.ts).toLocaleString() : '—'),
    },
    {
      key: 'decision',
      header: 'Decision',
      render: (d) => (
        <Badge variant={d.decision === 'ALLOW' ? 'success' : 'danger'}>
          {d.decision}
        </Badge>
      ),
    },
    { key: 'tool', header: 'Tool', render: (d) => d.tool || '—' },
    {
      key: 'principal',
      header: 'Principal',
      render: (d) => (
        <span className="font-mono text-xs">{d.principal || '—'}</span>
      ),
    },
    {
      key: 'determining_policies',
      header: 'Policy',
      render: (d) =>
        d.determining_policies.length ? (
          <span className="font-mono text-xs">
            {d.determining_policies.join(', ')}
          </span>
        ) : (
          '—'
        ),
    },
    {
      key: 'latency_ms',
      header: 'Latency',
      align: 'right',
      render: (d) => (d.latency_ms != null ? `${d.latency_ms} ms` : '—'),
    },
  ];

  return (
    <div className="space-y-4">
      <p className="text-sm text-gray-500 dark:text-gray-400">
        Live policy decisions from the governance gateway (Cedar). Read directly
        from the decision log — this is the authoritative record of what was
        allowed or denied.
      </p>

      <div className="flex flex-wrap items-end gap-3">
        <div className="w-44">
          <Select
            label="Decision"
            name="decision"
            options={DECISION_OPTIONS}
            value={decision}
            onChange={(e) => setDecision(e.target.value)}
          />
        </div>
        <div className="w-48">
          <Select
            label="Window"
            name="window"
            options={WINDOW_OPTIONS}
            value={windowHours}
            onChange={(e) => setWindowHours(e.target.value)}
          />
        </div>
        <div className="w-56">
          <Select
            label="Tenant"
            name="decision-tenant"
            options={[{ value: '', label: 'All tenants' }]}
            placeholder="Filter by tenant (org_id)"
            value={tenant}
            onChange={(e) => setTenant(e.target.value)}
          />
        </div>
        <div className="ml-auto">
          <Button variant="secondary" onClick={() => refetch()} isLoading={isFetching}>
            Refresh
          </Button>
        </div>
      </div>

      {isError && (
        <Alert variant="error">
          {errorMessage(error)}{' '}
          <button className="underline" onClick={() => refetch()}>
            Retry
          </button>
        </Alert>
      )}

      {data?.truncated && (
        <Alert variant="warning">
          Showing the most recent decisions only — older entries were truncated.
          Narrow the time window to see a complete set.
        </Alert>
      )}

      <Table<GovernanceDecision>
        columns={columns}
        data={data?.items ?? []}
        keyExtractor={(d) => `${d.request_id ?? ''}-${d.ts}`}
        isLoading={isLoading}
        emptyMessage="No decisions in this window. Decisions appear here once agents call governed tools."
      />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Shared detail modal
// ---------------------------------------------------------------------------

function ToolDetailModal({
  tool,
  onClose,
}: {
  tool: GovernanceTool | null;
  onClose: () => void;
}) {
  return (
    <Modal isOpen={tool !== null} onClose={onClose} title={tool?.name} size="lg">
      {tool && (
        <dl className="space-y-3 text-sm">
          <Field label="Tool name" value={tool.name} />
          <Field label="Tenant (org_id)" value={tool.tenant} />
          <Field label="Owner" value={tool.owner || '—'} />
          <Field label="Handler" value={tool.handler || '—'} />
          <div>
            <dt className="font-medium text-gray-500 dark:text-gray-400">Status</dt>
            <dd className="mt-1">
              <Badge variant={statusVariant(tool.status)}>{tool.status}</Badge>
            </dd>
          </div>
          <Field label="Description" value={tool.description || '—'} />
          {tool.reject_reason && (
            <Field label="Reject reason" value={tool.reject_reason} />
          )}
          <Field
            label="Registered"
            value={tool.created_at ? new Date(tool.created_at).toLocaleString() : '—'}
          />
          {tool.reviewed_by && <Field label="Reviewed by" value={tool.reviewed_by} />}
        </dl>
      )}
    </Modal>
  );
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="font-medium text-gray-500 dark:text-gray-400">{label}</dt>
      <dd className="mt-1 text-gray-900 dark:text-white break-words">{value}</dd>
    </div>
  );
}

export default function Governance() {
  return (
    <div className="p-6 max-w-6xl mx-auto">
      <div className="mb-4">
        <h1 className="text-2xl font-semibold text-gray-900 dark:text-white">
          Governance
        </h1>
        <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
          Catalogue of governed tools and their review status. Access is enforced
          by the governance gateway (Cedar) — this registry is the review record.
        </p>
      </div>

      <Tabs defaultValue="registry">
        <TabsList>
          <Tab value="registry">Registry</Tab>
          <Tab value="review">Review queue</Tab>
          <Tab value="audit">Audit trail</Tab>
        </TabsList>
        <TabPanel value="registry">
          <RegistryTab />
        </TabPanel>
        <TabPanel value="review">
          <ReviewTab />
        </TabPanel>
        <TabPanel value="audit">
          <AuditTab />
        </TabPanel>
      </Tabs>
    </div>
  );
}
