#include <openssl/engine.h>
#include <openssl/opensslv.h>
#include <openssl/asn1t.h>

#include <cstring>
#include <string>

void DEBUG_STDOUT(const char* szFormat, ...)
{
	char *envVar = getenv("TESTENGINE_DEBUG");
	if (envVar && strlen(envVar) && strcmp(envVar, "1") == 0)
	{
		va_list args;
		va_start(args, szFormat);
		fprintf(stdout, szFormat, args);
		fflush(stdout);
	}
}

const char *testengine_engine_id 		    = "testengine";
const char *testengine_engine_name 		    = "TestEngine engine";
const char *testengine_ec_method_name 	    = "TestEngine EC method";

static EC_KEY_METHOD *testengine_ec_key_method = NULL;
static const EC_KEY_METHOD *ossl_ec_key_method = NULL;

static EVP_PKEY_ASN1_METHOD* testengine_ec_pkey_asn1_method = NULL;
static const EVP_PKEY_ASN1_METHOD* ossl_ec_pkey_asn1_method = NULL;
static EVP_PKEY_METHOD* testengine_ec_pkey_method = NULL;
static const EVP_PKEY_METHOD *ossl_ec_pkey_method = NULL;

static int pkey_nids[] = {
	EVP_PKEY_EC,
	0
};

static int pkey_asn1_nids[] = {
	EVP_PKEY_EC,
	0
};

static int testengine_initialize_ec_key_meth()
{
	DEBUG_STDOUT("\n --> testengine_initialize_ec_key_meth()\n");

	ossl_ec_key_method = EC_KEY_OpenSSL();
	if (ossl_ec_key_method == NULL)
	{
		DEBUG_STDOUT("\n --> testengine_initialize_ec_key_meth() KO\n");
		return 0;
	}

	testengine_ec_key_method = EC_KEY_METHOD_new(ossl_ec_key_method);
	if (testengine_ec_key_method == NULL)
	{
		DEBUG_STDOUT("\n --> testengine_initialize_ec_key_meth() KO\n");
		return 0;
	}

	DEBUG_STDOUT("\n --> testengine_initialize_ec_key_meth() OK\n");
	return 1;
}

static EC_KEY_METHOD *testengine_get_ec_key_method(void)
{
	DEBUG_STDOUT("\n --> testengine_get_ec_key_method() OK\n");
	return testengine_ec_key_method;
}

static int testengine_initialize_ec_pkey_asn1_meth(void)
{
	DEBUG_STDOUT("\n --> testengine_initialize_ec_pkey_asn1_meth()\n");

	ossl_ec_pkey_asn1_method = EVP_PKEY_asn1_find(NULL, EVP_PKEY_EC);
	if (ossl_ec_pkey_asn1_method == NULL)
	{
		DEBUG_STDOUT("\n --> testengine_initialize_ec_pkey_asn1_meth() KO\n");
		return 0;
	}

	testengine_ec_pkey_asn1_method = EVP_PKEY_asn1_new(EVP_PKEY_EC, ASN1_PKEY_SIGPARAM_NULL, "EC", "TestEngine EC method");
	if (testengine_ec_pkey_asn1_method == NULL)
	{
		DEBUG_STDOUT("\n --> testengine_initialize_ec_pkey_asn1_meth() KO\n");
		return 0;
	}

	EVP_PKEY_asn1_copy(testengine_ec_pkey_asn1_method, ossl_ec_pkey_asn1_method);

	DEBUG_STDOUT("\n --> testengine_initialize_ec_pkey_asn1_meth() OK\n");
	return 1;
}

static int testengine_initialize_ec_pkey_meth(void)
{
	DEBUG_STDOUT("\n --> testengine_initialize_ec_pkey_meth()\n");

	ossl_ec_pkey_method = EVP_PKEY_meth_find(EVP_PKEY_EC);
	if (ossl_ec_pkey_method == NULL)
	{
		DEBUG_STDOUT("\n --> testengine_initialize_ec_pkey_meth() KO\n");
		return 0;
	}

	testengine_ec_pkey_method = EVP_PKEY_meth_new(EVP_PKEY_EC, 0);
	if (testengine_ec_pkey_method == NULL)
	{
		DEBUG_STDOUT("\n --> testengine_initialize_ec_pkey_meth() KO\n");
		return 0;
	}

	EVP_PKEY_meth_copy(testengine_ec_pkey_method, ossl_ec_pkey_method);

	DEBUG_STDOUT("\n --> testengine_initialize_ec_pkey_meth() OK\n");
	return 1;
}

static int testengine_pkey_asn1_meths(ENGINE *e, EVP_PKEY_ASN1_METHOD **ameth, const int **nids, int nid)
{
	DEBUG_STDOUT("\n --> testengine_pkey_asn1_meths()\n");

	if (!ameth)
	{
		DEBUG_STDOUT("\n     ameth == NULL\n");

		*nids = pkey_asn1_nids;
		return (sizeof(pkey_asn1_nids) - 1) / sizeof(pkey_asn1_nids[0]);
	}

	DEBUG_STDOUT("\n     ameth != NULL\n");

	switch (nid)
	{
		case EVP_PKEY_EC:
		{
			DEBUG_STDOUT("\n     nid == EVP_PKEY_EC\n");

			*ameth = testengine_ec_pkey_asn1_method;
			return 1; //	success
		}
	}

	*ameth = NULL;
	return 0;
}

static int testengine_pkey_meths(ENGINE *e, EVP_PKEY_METHOD **pmeth, const int **nids, int nid)
{
	DEBUG_STDOUT("\n --> testengine_pkey_meths()\n");

	if (!pmeth)
	{
		DEBUG_STDOUT("\n     pmeth == NULL\n");

		*nids = pkey_nids;
		return (sizeof(pkey_nids) - 1) / sizeof(pkey_nids[0]);
	}

	DEBUG_STDOUT("\n     pmeth != NULL\n");

	switch (nid)
	{
		case EVP_PKEY_EC:
		{
			*pmeth = testengine_ec_pkey_method;
			return 1; //	success
		}
	}

	*pmeth = NULL;
	return 0;
}

static int bind_helper(ENGINE *e)
{
	DEBUG_STDOUT("\n --> bind_helper()\n");

	if (	!ENGINE_set_id(e, testengine_engine_id) 
		||	!ENGINE_set_name(e, testengine_engine_name)

		||	!testengine_initialize_ec_key_meth()
		||  !testengine_initialize_ec_pkey_asn1_meth()
		||	!testengine_initialize_ec_pkey_meth()

		||	!ENGINE_set_EC(e, testengine_get_ec_key_method())
		||  !ENGINE_set_pkey_asn1_meths(e, testengine_pkey_asn1_meths)
		||	!ENGINE_set_pkey_meths(e, testengine_pkey_meths)
	)
	{
		goto err;
	}

	return 1;

err:

	if (testengine_ec_key_method)
		EC_KEY_METHOD_free(testengine_ec_key_method);
	testengine_ec_key_method = NULL;
	if (testengine_ec_pkey_method)
		EVP_PKEY_meth_free(testengine_ec_pkey_method);
	testengine_ec_pkey_method = NULL;
	if (testengine_ec_pkey_asn1_method)
		EVP_PKEY_asn1_free(testengine_ec_pkey_asn1_method);
	testengine_ec_pkey_asn1_method = NULL;

	return 0;
}

static int bind_testengine(ENGINE *e, const char *id)
{
	DEBUG_STDOUT("\n --> bind_testengine()\n");

	if (id && (strcmp(id, testengine_engine_id) != 0))
	{
		fprintf(stderr, "Bad Engine ID - Got : %s, Expected : %s\n", id, testengine_engine_id);
		return 0;
	}
	if (!bind_helper(e)) 
	{
		fprintf(stderr, "bind_helper() failed\n");
		return 0;
	}

	DEBUG_STDOUT("\n --> bind_testengine() OK\n");
	return 1;
}

extern "C" {
	IMPLEMENT_DYNAMIC_CHECK_FN()
	IMPLEMENT_DYNAMIC_BIND_FN(bind_testengine)
}
