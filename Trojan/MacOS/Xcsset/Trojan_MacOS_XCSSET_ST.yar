
rule Trojan_MacOS_XCSSET_ST{
	meta:
		description = "Trojan:MacOS/XCSSET.ST,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {63 00 75 00 72 00 6c 00 20 00 2d 00 66 00 73 00 6b 00 4c 00 20 00 2d 00 64 00 20 00 } //1 curl -fskL -d 
		$a_00_1 = {6f 00 73 00 3d 00 24 00 28 00 75 00 6e 00 61 00 6d 00 65 00 20 00 2d 00 73 00 29 00 26 00 70 00 3d 00 } //1 os=$(uname -s)&p=
		$a_02_2 = {68 00 74 00 74 00 70 00 [0-30] 2e 00 72 00 75 00 2f 00 } //1
		$a_00_3 = {7c 00 20 00 73 00 68 00 20 00 3e 00 2f 00 64 00 65 00 76 00 2f 00 6e 00 75 00 6c 00 6c 00 20 00 32 00 3e 00 26 00 31 00 20 00 26 00 } //1 | sh >/dev/null 2>&1 &
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}