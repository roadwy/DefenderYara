
rule Trojan_BAT_Crysan_BXJ_MTB{
	meta:
		description = "Trojan:BAT/Crysan.BXJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {4a 00 72 01 00 00 70 72 0d 00 00 70 28 14 00 00 0a 26 2a } //1
		$a_80_1 = {2e 75 73 2e 61 72 63 68 69 76 65 2e 6f 72 67 } //.us.archive.org  1
	condition:
		((#a_00_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}