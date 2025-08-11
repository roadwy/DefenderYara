
rule Trojan_BAT_Strictor_PA_MTB{
	meta:
		description = "Trojan:BAT/Strictor.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 05 17 58 28 6a 00 00 06 28 43 00 00 0a 5d 13 05 11 06 09 11 05 94 58 28 6b 00 00 06 28 43 00 00 0a 5d 13 06 09 11 05 94 13 0d 09 11 05 09 11 06 94 9e 09 11 06 11 0d 9e 09 09 11 05 94 09 11 06 94 58 20 00 01 00 00 5d 94 13 0e 11 07 11 0c 02 11 0c 91 11 0e 61 28 44 00 00 0a 9c 11 0c 17 58 13 0c 11 0c 02 8e 69 32 96 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}