dir		= {{ ca_cert_dir }}			  # Where everything is kept

# ####################################################################
[ ca ]
default_ca	= CA_default		# The default ca section

####################################################################
[ CA_default ]

certs		= $dir			  # Where the issued certs are kept
crl_dir		= $dir			  # Where the issued crl are kept
database	= $dir/index.txt
new_certs_dir	= $dir			  # default place for new certs.

certificate	= $dir/proxpyca.crt 	  # The CA certificate
serial		= $dir/serial 		  # The current serial number
crlnumber	= $dir/crlnumber	  # the current crl number
					  # must be commented out to leave a V1 CRL
crl		= $dir/proxpy.pem	  # The current CRL
private_key	= $dir/proxpy.key	  # The private key
RANDFILE	= $dir/.rand		  # private random number file

name_opt 	= ca_default		  # Subject Name options
cert_opt 	= ca_default		  # Certificate field options

default_days	= 365			  # how long to certify for
default_md	= sha1			  # use public key default MD
preserve	= no			  # keep passed DN ordering

policy		= policy_match

# For the CA policy
[ policy_match ]
countryName		= match
organizationName	= supplied
organizationalUnitName	= supplied
commonName		= supplied

####################################################################
[ req ]
 default_bits           = 1024
 distinguished_name     = req_distinguished_name
 prompt                 = no
[ req_distinguished_name ]
 C                      = IT
 CN                     = {{ common_name }}
 O                      = proxpy
 OU                     = proxpyServer

[ v3_ca ] 
basicConstraints = CA:TRUE 
subjectKeyIdentifier = hash 
authorityKeyIdentifier = keyid:always,issuer:always 
