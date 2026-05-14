
rule Trojan_MacOS_ClawHavoc_DB_MTB{
	meta:
		description = "Trojan:MacOS/ClawHavoc.DB!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {65 00 63 00 68 00 6f 00 [0-ff] 62 00 61 00 73 00 65 00 36 00 34 00 20 00 2d 00 44 00 } //1
		$a_00_1 = {62 00 61 00 73 00 68 00 } //1 bash
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}