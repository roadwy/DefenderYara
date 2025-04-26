
rule Backdoor_Linux_Gafgyt_BN_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.BN!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 63 68 6d 6f 64 20 37 37 37 20 2f 74 6d 70 2f 2e 61 6d 6b } //1 /bin/busybox chmod 777 /tmp/.amk
		$a_01_1 = {2f 76 61 72 2f 53 6f 66 69 61 } //1 /var/Sofia
		$a_01_2 = {74 6d 70 2f 2e 61 6d 6b 20 2d 72 20 2f 68 75 61 77 65 69 } //1 tmp/.amk -r /huawei
		$a_01_3 = {3c 4e 65 77 44 6f 77 6e 6c 6f 61 64 55 52 4c 3e 24 28 65 63 68 6f 20 48 55 41 57 45 49 55 50 4e 50 29 3c 2f 4e 65 77 44 6f 77 6e 6c 6f 61 64 55 52 4c 3e } //1 <NewDownloadURL>$(echo HUAWEIUPNP)</NewDownloadURL>
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}