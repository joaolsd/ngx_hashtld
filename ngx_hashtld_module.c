#include <nginx.h>
#include <ngx_http.h>
#include <ngx_http_variables.h>

#define MAX_DOMAINS 512
char *test_domains[MAX_DOMAINS];
int num_domains;

int djb2_hash(char *str, int num_buckets);

static ngx_int_t
ngx_hashtld_get(ngx_http_request_t *r, ngx_http_variable_value_t *v, \
        uintptr_t data) {
          
    int tld_index;
    char *new_domain;

    // The ICANN gTLD experiment direct-to-TLD approach uses random-picked TLDs
    // to put them in the config (newadcfg)
    tld_index = ( rand() % (num_domains) );

    // Look up the gTLD to issue
    new_domain = test_domains[tld_index];

    v->len = strlen(new_domain);
    v->data = (u_char *)new_domain;

    v->valid = 1;
    v->not_found = 0;
    v->no_cacheable = 0;

    return NGX_OK;
}

int read_test_domains(char *domain_list, ngx_cycle_t *cycle) {
  FILE *f_dl;
  // If there is a domain list to load, load it
  if (strlen(domain_list) !=0 ) {
    f_dl = fopen(domain_list, "r");
    if (f_dl == NULL) {
      ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                    "Could not open domain list %s", domain_list);
      return NGX_ERROR;
    }
  } else {
    ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                  "domain list file name is empty");
    return NGX_ERROR;
  }
  // Read the domain list
  int max_line_len = 128;
  char *line_buffer = (char *)calloc(max_line_len, 1);
  num_domains = 0;
  while ( (line_buffer = fgets(line_buffer, max_line_len, f_dl)) != NULL) {
    line_buffer[strlen(line_buffer)-1] = '\0';
    test_domains[num_domains] = strdup(line_buffer);
    num_domains++;
    if (num_domains > MAX_DOMAINS) {
      ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                    "Too many test domains. Maximum is %d", MAX_DOMAINS);
      return NGX_ERROR;
    }
  }
  free(line_buffer);
  // for (int i=0; i<num_domains;i++) {
  // 	printf("%s\n",test_domains[i]);
  // }
  ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                "Read %d domains from domain list", num_domains);
  
  return num_domains;
}

static ngx_int_t
ngx_hashtld_init_process(ngx_cycle_t *cycle) {
    srand(time(0)); // Seed the random generator
    // Load list of gTLDs from file
    char *domain_list = "/usr/local/dns/domain_list.txt";
    num_domains = read_test_domains(domain_list, cycle);
    if (num_domains == NGX_ERROR) {
      return NGX_ERROR;
    } else {
      return NGX_OK;
    }
}

static void
ngx_hashtld_exit_process(ngx_cycle_t *cycle) {
  return;
}

static ngx_str_t ngx_hashtld_variable_name = ngx_string("hashtld");

static ngx_int_t ngx_hashtld_add_variables(ngx_conf_t *cf)
{
  ngx_http_variable_t* var = ngx_http_add_variable(
          cf,
          &ngx_hashtld_variable_name,
          NGX_HTTP_VAR_NOHASH);

  if (var == NULL) {
      return NGX_ERROR;
  }

  var->get_handler = ngx_hashtld_get;

  return NGX_OK;
}

static ngx_http_module_t  ngx_hashtld_module_ctx = {
  ngx_hashtld_add_variables,     /* preconfiguration */
  NULL,                        /* postconfiguration */

  NULL,        /* create main configuration */
  NULL,        /* init main configuration */

  NULL,        /* create server configuration */
  NULL,        /* merge server configuration */

  NULL,        /* create location configuration */
  NULL         /* merge location configuration */
};

static ngx_command_t  ngx_hashtld_module_commands[] = {
  ngx_null_command
};

ngx_module_t  ngx_hashtld_module = {
  NGX_MODULE_V1,
  &ngx_hashtld_module_ctx,      /* module context */
  ngx_hashtld_module_commands,  /* module directives */
  NGX_HTTP_MODULE,                /* module type */
  NULL,                           /* init master */
  NULL,                           /* init module */
  ngx_hashtld_init_process,          /* init process */
  NULL,                           /* init thread */
  NULL,                           /* exit thread */
  ngx_hashtld_exit_process,          /* exit process */
  NULL,                           /* exit master */
  NGX_MODULE_V1_PADDING
};