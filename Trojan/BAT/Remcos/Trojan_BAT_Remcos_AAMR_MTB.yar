
rule Trojan_BAT_Remcos_AAMR_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AAMR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 00 02 03 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 16 03 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 8e 69 28 90 01 01 00 00 0a 28 90 01 01 00 00 06 26 2a 90 00 } //4
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 43 68 61 72 41 72 72 61 79 } //1 FromBase64CharArray
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}