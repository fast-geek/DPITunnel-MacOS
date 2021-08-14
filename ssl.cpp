#include "dpitunnel-cli.h"

#include "ssl.h"

extern struct Settings_s Settings;

int load_ca_bundle() {
	std::ifstream file;
	file.open(Settings.ca_bundle_path);
	if(!file) {
		std::cerr << "Failed to open CA Bundle (SSL certs). File "
				<< Settings.ca_bundle_path << " not found" << std::endl;
		return -1;
	}

	std::stringstream stream;
	stream << file.rdbuf();
	Settings.ca_bundle = stream.str();

	return 0;
}

X509_STORE *gen_x509_store() {
	BIO *cbio = BIO_new_mem_buf(Settings.ca_bundle.c_str(), Settings.ca_bundle.size());
	X509_STORE *cts;
	if((cts = X509_STORE_new()) == NULL)
		return NULL;
	STACK_OF(X509_INFO) *inf;
	if(!cts || !cbio)
		return NULL;

	inf = PEM_X509_INFO_read_bio(cbio, NULL, NULL, NULL);
	if(!inf) {
		BIO_free(cbio);
		return NULL;
	}

	for(int i = 0; i < sk_X509_INFO_num(inf); i++) {
		X509_INFO *itmp = sk_X509_INFO_value(inf, i);
		if(itmp->x509)
			X509_STORE_add_cert(cts, itmp->x509);
		if(itmp->crl)
			X509_STORE_add_crl(cts, itmp->crl);
	}

	sk_X509_INFO_pop_free(inf, X509_INFO_free);
	BIO_free(cbio);

	return cts;
}
