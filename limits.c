#include "limits.h"

int scan_limit = 10;

int consecutive_score = 4000;
int consecutive_hits = 4;
int consecutive_jump = 5;
int consecutive_threshold = 50;

int range_tolerance = 5;  // A maximum number of non-matched lines tolerated inside a matching range
int min_match_lines = 10; // Minimum number of lines matched for a match range to be acepted
int min_match_hits  = 5;  // Minimum number of snippet ID hits to produce a snippet match

const int rank_items = 1000; // Number of items to evaluate in component and path rankings

const int max_vulnerabilities = 50; // Show only the first N vulnerabilities


void recurse_directory(char *name)
{
	DIR *dir;
	struct dirent *entry;
	bool read = false;

	if (!(dir = opendir(name))) return;

	while ((entry = readdir(dir)))
	{
		if (!strcmp(entry->d_name,".") || !strcmp(entry->d_name,"..")) continue;

		read = true;
		char *path =calloc (MAX_PATH, 1);
		sprintf (path, "%s/%s", name, entry->d_name);
			
		if (entry->d_type == DT_DIR)
				recurse_directory(path);

		else if (is_file(path))
		{

			/* Scan file directly */
			scan_data scan = scan_data_init(path);

			bool wfp = false;
			if (extension(path)) if (!strcmp(extension(path), "wfp")) wfp = true;

			if (wfp)
				wfp_scan(&scan);
			else
				ldb_scan(&scan);

			scan_data_free(scan);
		}

		free(path);
	}

	if (read) closedir(dir);
}
