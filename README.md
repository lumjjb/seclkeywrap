# seclkeywrap

This is the underlying library to perform key wrapping/unwrapping using ISecL Key Broker. It is integrated into the build/runtime tools at the following repos:
- https://github.com/lumjjb/skopeo/tree/sample_integration
- https://github.com/lumjjb/cri-o/tree/1.16_encryption_sample_integration


# Example

## Encrypting with skopeo

wpm and wlagent used in hack/ in:

https://github.com/lumjjb/seclkeywrap/ 

```
vagrant@ubuntu-bionic:~/go/src/github.com/containers/skopeo$ ./skopeo copy  docker://docker.io/library/nginx:latest oci:nginx_local
Getting image source signatures
Copying blob 68ced04f60ab done
Copying blob 28252775b295 done
Copying blob a616aa3b0bf2 done
Copying config 841217fb19 done
Writing manifest to image destination
Storing signatures

vagrant@ubuntu-bionic:~/go/src/github.com/containers/skopeo$ ./skopeo copy --encryption-key secl:any oci:nginx_local oci:nginx_secl_enc
Getting image source signatures
Copying blob 68ced04f60ab done
Copying blob 28252775b295 done
Copying blob a616aa3b0bf2 done
Copying config 841217fb19 done
Writing manifest to image destination
Storing signatures

vagrant@ubuntu-bionic:~/go/src/github.com/containers/skopeo$ ./skopeo copy --decryption-key secl:enabled oci:nginx_secl_enc oci:nginx_secl_dec
Getting image source signatures
Copying blob ac40d5fa6e19 done
Copying blob fbfc8f780770 done
Copying blob 7225a4c3ec8b done
Copying config 841217fb19 done
Writing manifest to image destination
Storing signatures



# ASSET TAG CONVENTION
vagrant@ubuntu-bionic:~/go/src/github.com/containers/skopeo$ ./skopeo copy --encryption-key secl:assettag1:value  oci:nginx_local oci:nginx_secl_enc
Getting image source signatures
Copying blob 68ced04f60ab done
Copying blob 28252775b295 done
Copying blob a616aa3b0bf2 done
FATA[0002] Unable to finalize encryption: Unable to obtain sym key from broker: Not Implemented: asset tag implementation for encryption
```


## Decrypingt with cri-o

```
# push to registry
vagrant@ubuntu-bionic:~/go/src/github.com/containers/skopeo$ ./skopeo copy --dest-tls-verify=false  oci:nginx_secl_enc docker://localhost:5000/nginx_secl_enc:latest
Getting image source signatures
Copying blob 58d4bab3bb94 skipped: already exists
Copying blob a70e107f61cb skipped: already exists
Copying blob ba55e928631a [--------------------------------------] 0.0b / 0.0b
Writing manifest to image destination
Storing signatures

vagrant@ubuntu-bionic:~/go/src/github.com/cri-o/cri-o$ sudo bin/crio &
[1] 15940
vagrant@ubuntu-bionic:~/go/src/github.com/cri-o/cri-o$ sudo crictl -r unix:///var/run/crio/crio.sock rmi localhost:5000/nginx_secl_enc:latest
ERRO[0000] no such image localhost:5000/nginx_secl_enc:latest
FATA[0000] unable to remove the image(s)
vagrant@ubuntu-bionic:~/go/src/github.com/cri-o/cri-o$ sudo crictl -r unix:///var/run/crio/crio.sock pull localhost:5000/nginx_secl_enc:latest
FATA[0000] pulling image failed: rpc error: code = Unknown desc = Error decrypting layer sha256:5070e5ee4a741f3f8722583b4b1df72af913551e9a6e5feb1a6b1d5fe2d4073e: missing private key needed for decryption
vagrant@ubuntu-bionic:~/go/src/github.com/cri-o/cri-o$
vagrant@ubuntu-bionic:~/go/src/github.com/cri-o/cri-o$
vagrant@ubuntu-bionic:~/go/src/github.com/cri-o/cri-o$
vagrant@ubuntu-bionic:~/go/src/github.com/cri-o/cri-o$ fg
sudo bin/crio
^C^C

### Try with secl parameters
vagrant@ubuntu-bionic:~/go/src/github.com/cri-o/cri-o$ sudo bin/crio --decryption-secl-parameters secl:enabled &
[1] 16007
vagrant@ubuntu-bionic:~/go/src/github.com/cri-o/cri-o$ sudo crictl -r unix:///var/run/crio/crio.sock rmi localhost:5000/nginx_secl_enc:latest
ERRO[0000] no such image localhost:5000/nginx_secl_enc:latest
FATA[0000] unable to remove the image(s)
vagrant@ubuntu-bionic:~/go/src/github.com/cri-o/cri-o$ sudo crictl -r unix:///var/run/crio/crio.sock pull localhost:5000/nginx_secl_enc:latest
Image is up to date for localhost:5000/nginx_secl_enc@sha256:ec31b7ccba89943c10d12fa8595b51e76f77d0f7dad3aa776f02a0b1959cab07
```
