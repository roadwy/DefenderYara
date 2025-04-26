
rule Trojan_BAT_Walgentz_Z_MTB{
	meta:
		description = "Trojan:BAT/Walgentz.Z!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {2f 61 70 69 2e 70 68 70 } //1 /api.php
		$a_81_1 = {2f 61 70 69 2d 64 65 62 75 67 2e 70 68 70 } //1 /api-debug.php
		$a_81_2 = {3f 73 74 61 74 75 73 3d 31 26 77 61 6c 6c 65 74 73 3d } //1 ?status=1&wallets=
		$a_81_3 = {3f 73 74 61 74 75 73 3d 32 26 77 61 6c 6c 65 74 73 3d } //1 ?status=2&wallets=
		$a_81_4 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //1 DownloadString
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}