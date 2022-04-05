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

nt consecutive_score = 4000;
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

/* Scan a file */
static bool scanner_file_proc(scanner_object_t *s, char *path)
{
    bool state = true;
    char *wfp_buffer;
    char *ext = strrchr(path, '.');
    if (!ext)
        return state;

    char f_extension[strlen(ext) + 3];

    /*File extension filter*/
    sprintf(f_extension, " %s,", ext);

    if (strstr(EXCLUDED_EXTENSIONS, f_extension))
    {
        log_trace("Excluded extension: %s", ext);
        scanner_write_none_result(s, path); //add none id to ignored files
        return true; //avoid filtered extensions
    } 
    
    s->status.state = SCANNER_STATE_WFP_CALC; //update scanner state
    
    //If we have a wfp file, add the content to the main wfp file.
    if (!strcmp(ext, ".wfp"))
    {
        log_debug("is a wfp file: %s", path);
        long len = 0;
        wfp_buffer = read_file(path, &len);
        
        //ensure line end character
        wfp_buffer[len] = '\n';
        s->status.wfp_files += key_count(wfp_buffer,"file=") - 1; //correct the total files number
    }
    else
    {
         wfp_buffer = calloc(MAX_FILE_SIZE, 1);
        *wfp_buffer = 0;
        scanner_wfp_capture(path,NULL, wfp_buffer);
    }
    
    if (*wfp_buffer)
    {
        FILE *wfp_f = fopen(s->wfp_path, "a+");
        fprintf(wfp_f, "%s", wfp_buffer);
        fclose(wfp_f);
        state = false;
        s->status.wfp_files++; //update scanner proc. files
    }
    else
    {
        scanner_write_none_result(s, path); //add none id to ignored files
        log_trace("No wfp: %s", path);
    }

    free(wfp_buffer);

    if (s->callback && s->status.wfp_files % 100 == 0)
        s->callback(&s->status,SCANNER_EVT_WFP_CALC_IT);
    
    return state;
}
