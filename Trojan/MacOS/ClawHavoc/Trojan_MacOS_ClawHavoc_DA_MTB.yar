
rule Trojan_MacOS_ClawHavoc_DA_MTB{
	meta:
		description = "Trojan:MacOS/ClawHavoc.DA!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {26 00 26 00 20 00 63 00 75 00 72 00 6c 00 20 00 2d 00 4f 00 20 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 } //1 && curl -O http://
		$a_00_1 = {26 00 26 00 20 00 78 00 61 00 74 00 74 00 72 00 20 00 2d 00 63 00 } //1 && xattr -c
		$a_00_2 = {26 00 26 00 20 00 63 00 68 00 6d 00 6f 00 64 00 20 00 2b 00 78 00 } //1 && chmod +x
		$a_00_3 = {26 00 26 00 20 00 2e 00 2f 00 } //1 && ./
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}