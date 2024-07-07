
rule Trojan_BAT_Heracles_DAM_MTB{
	meta:
		description = "Trojan:BAT/Heracles.DAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 04 06 11 04 06 6f 90 01 01 00 00 0a 1e 5b 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 06 11 04 06 6f 90 01 01 00 00 0a 1e 5b 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 06 17 6f 90 01 01 00 00 0a 08 06 6f 90 01 01 00 00 0a 17 73 90 01 01 00 00 0a 13 05 11 05 09 16 09 8e 69 6f 90 01 01 00 00 0a de 08 90 00 } //4
		$a_01_1 = {47 65 74 42 79 74 65 73 } //1 GetBytes
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}