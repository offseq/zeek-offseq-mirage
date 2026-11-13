##! Loads the OffSeq Mirage Feed Zeek Intel file, refreshes it on a timer
##! and removes indicators that drop out of the feed.

@load base/frameworks/intel
@load base/utils/exec

module OffSeqMirage;

export {
	## Where the Intel file is downloaded from.
	const url = "https://feeds.offseq.com/mirage-feed/latest/zeek/mirage.intel" &redef;

	## Local copy read by the Intel framework, relative to Zeek's working directory.
	const intel_file = "mirage.intel" &redef;

	## How often to download the file. The feed is rebuilt daily.
	const refresh_interval = 6 hrs &redef;

	## Set to F to keep intel_file up to date yourself (replace it atomically with mv).
	const fetch = T &redef;
}

const stream_name = "intel-offseq-mirage";
const meta_source = "mirage-feed";

global seen: set[string, Intel::Type];
global previous: set[string, Intel::Type];

event OffSeqMirage::refresh()
	{
	local tmp = intel_file + ".tmp";
	local cmd = fmt("curl -fsS --max-time 120 -o %s %s && mv -f %s %s",
	                safe_shell_quote(tmp), safe_shell_quote(url),
	                safe_shell_quote(tmp), safe_shell_quote(intel_file));

	when [cmd] ( local r = Exec::run([$cmd=cmd]) )
		{
		if ( r$exit_code != 0 )
			Reporter::warning(fmt("OffSeqMirage: download of %s failed (exit %d)", url, r$exit_code));
		}

	schedule refresh_interval { OffSeqMirage::refresh() };
	}

event Intel::read_entry(desc: Input::EventDescription, tpe: Input::Event, item: Intel::Item)
	{
	if ( desc$name == stream_name )
		add seen[item$indicator, item$indicator_type];
	}

event Input::end_of_data(name: string, source: string)
	{
	if ( name != stream_name )
		return;

	for ( [indicator, indicator_type] in previous )
		if ( [indicator, indicator_type] !in seen )
			Intel::remove([$indicator=indicator, $indicator_type=indicator_type,
			               $meta=[$source=meta_source]]);

	previous = seen;
	seen = set();
	}

event zeek_init()
	{
	if ( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER )
		return;

	# REREAD picks up each atomic replacement of the file
	Input::add_event([$source=intel_file, $reader=Input::READER_ASCII,
	                  $mode=Input::REREAD, $name=stream_name,
	                  $fields=Intel::Item, $ev=Intel::read_entry,
	                  $error_ev=Intel::read_error]);

	if ( fetch )
		event OffSeqMirage::refresh();
	}
