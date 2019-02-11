Build
======

$ sh ./autogen.sh
$ make

Run
====

The output contents is a base64 encoded and similar we expecte the input must be
base64 encoded.

* Show the platform status

  $ ./pspioctl --status

* To generate new PEK
 
  $ ./pspioctl --pek-gen

* To re-generate the PDH
 
  $ ./pspioctl --pdh-gen

* To generate CSR
 
  $ ./pspioctl --pek-csr

  Generated certificate will be saved in certs/output

* To import the CERTs

  $ ./pspioctl --pek-import

  Before issuing the command you must copy your a valid PEK and OCA
  certificates in certs/input/pek.b64 and certs/output/oca.b64.

* To export the PDH and identify of the platform

  $ ./pspioctl --pdh-export

  All the certificates will be saved in certs/output directory.

* To export the ID

  $ ./pspioctl --get-id

* To dump the contents of the certificate file

  $ ./pspioctl --decode-cert <filename>

