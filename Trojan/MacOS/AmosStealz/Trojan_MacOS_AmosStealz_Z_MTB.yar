
rule Trojan_MacOS_AmosStealz_Z_MTB{
	meta:
		description = "Trojan:MacOS/AmosStealz.Z!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {63 00 75 00 72 00 6c 00 20 00 2d 00 73 00 } //1 curl -s
		$a_00_1 = {24 00 28 00 65 00 63 00 68 00 6f 00 20 00 } //1 $(echo 
		$a_00_2 = {7c 00 20 00 62 00 61 00 73 00 65 00 36 00 34 00 20 00 2d 00 64 00 } //1 | base64 -d
		$a_00_3 = {7c 00 20 00 62 00 61 00 73 00 68 00 } //1 | bash
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}