
rule Trojan_BAT_Zusy_PTII_MTB{
	meta:
		description = "Trojan:BAT/Zusy.PTII!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 0e 00 28 ?? 00 00 0a 72 b4 04 00 70 6f 4e 00 00 0a 13 0f 11 07 11 0f 8e 69 6a 6f 4f 00 00 0a 00 11 07 6f 50 00 00 0a 13 10 11 10 11 0f 16 11 0f 8e 69 6f 51 00 00 0a 00 17 28 ?? 00 00 0a 00 11 04 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}