#include <nginx.h>
#include <ngx_http.h>
#include <ngx_http_variables.h>

#define MAX_DOMAINS 512
char *test_domains[MAX_DOMAINS];
int num_domains;

ngx_conf_t *my_cf;

int djb2_hash(char *str, int num_buckets);

static ngx_int_t
ngx_hashtld_get(ngx_http_request_t *r, ngx_http_variable_value_t *v, \
        uintptr_t data) {
          
    char *exp_str;
    int tld_index;
    char *new_domain;

    // The ICANN gTLD experiment uses a string of the form:
    // 6du-u$txrnd-c$ccid-s$txsec-i$txad-0.$cc2.dashnxdomain.net
    // 6du-ud77a895f-c68-s1535366734-i4f9b6b77-0.eu2.dashnxdomain.net
    // so this module needs to:
    // 1) be the last to get executed
    // 2) get the values of $txrnd, $ccid, $txsec and $txad

    ngx_int_t txrnd_idx;
    ngx_int_t ccid_idx;
    ngx_int_t txsec_idx;
    ngx_int_t txad_idx;

    ngx_http_variable_value_t *txrnd_val;
    ngx_http_variable_value_t *ccid_val;
    ngx_http_variable_value_t *txsec_val;
    ngx_http_variable_value_t *txad_val;
    
    ngx_str_t str_txrnd;
    ngx_str_t str_ccid;
    ngx_str_t str_txsec;
    ngx_str_t str_txad;
    
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "Start hashtld invocation");

    str_txrnd.data = (u_char *)"txrnd";
    str_txrnd.len = strlen((const char *)str_txrnd.data);
    str_ccid.data = (u_char *)"ccid";
    str_ccid.len = strlen((const char *)str_ccid.data);
    str_txsec.data = (u_char *)"txsec";
    str_txsec.len = strlen((const char *)str_txsec.data);
    str_txad.data = (u_char *)"txad";
    str_txad.len = strlen((const char *)str_txad.data);

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "Variable names are set");

    txrnd_idx = ngx_http_get_variable_index(my_cf, &str_txrnd);
    ccid_idx = ngx_http_get_variable_index(my_cf, &str_ccid);
    txsec_idx = ngx_http_get_variable_index(my_cf, &str_txsec);
    txad_idx = ngx_http_get_variable_index(my_cf, &str_txad);
    
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "Got variable indices");
    
    txrnd_val = ngx_http_get_indexed_variable(r, txrnd_idx);
    ccid_val = ngx_http_get_indexed_variable(r, ccid_idx);
    txsec_val = ngx_http_get_indexed_variable(r, txsec_idx);
    txad_val = ngx_http_get_indexed_variable(r, txad_idx);

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "Got variable values");

    exp_str = calloc(64, sizeof(char));
    
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "Building experiment string");

    
    // build experiment string from variable values
    exp_str = strcpy(exp_str, "6du-u");
    exp_str = strncat(exp_str, (char *)txrnd_val->data, txrnd_val->len);
    exp_str = strcat(exp_str, "-c");
    exp_str = strncat(exp_str, (char *)ccid_val->data, ccid_val->len);
    exp_str = strcat(exp_str, "-s");
    exp_str = strncat(exp_str, (char *)txsec_val->data, txsec_val->len);
    exp_str = strcat(exp_str, "-i");
    exp_str = strncat(exp_str, (char *)txad_val->data, txad_val->len);
    exp_str = strcat(exp_str, "-0");
    
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "Experiment string: %s", exp_str);

    // Hash the experiment string
    tld_index = djb2_hash(exp_str, num_domains);
    // Use the hash to look up the gTLD to issue
    new_domain = test_domains[tld_index];

    v->len = strlen(new_domain);
    v->data = (u_char *)new_domain;

    v->valid = 1;
    v->not_found = 0;
    v->no_cacheable = 0;
    
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "Converted experiment %s into domain %s", exp_str, new_domain);

    return NGX_OK;
}

int djb2_hash(char *str, int num_buckets) {
	unsigned long hash = 5381;
	int c;
	while ((c = *str++)) {
		hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
	}
	return (int)(hash % num_buckets);
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
  // for (int i=0; i<num_domains;i++) {
  // 	printf("%s\n",test_domains[i]);
  // }
  ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                "Read %d domains from domain list", num_domains);
  
  return num_domains;
}

static ngx_int_t
ngx_hashtld_init_process(ngx_cycle_t *cycle) {
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
  my_cf = cf;
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