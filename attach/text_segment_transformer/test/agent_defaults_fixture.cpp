/* SPDX-License-Identifier: MIT
 *
 * Minimal shared object used by the agent-defaults unit tests. The test
 * dlopen()s it and uses this symbol as the dladdr anchor, so its on-disk
 * directory stands in for the transformer's install directory.
 */
extern "C" void
bpftime_agent_defaults_anchor()
{
}
