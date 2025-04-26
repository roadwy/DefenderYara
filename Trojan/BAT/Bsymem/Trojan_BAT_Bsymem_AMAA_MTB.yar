
rule Trojan_BAT_Bsymem_AMAA_MTB{
	meta:
		description = "Trojan:BAT/Bsymem.AMAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 06 11 10 17 8d ?? ?? 00 01 25 16 11 05 11 10 9a 1f 10 28 ?? 00 00 0a 86 9c 6f ?? 00 00 0a 00 11 10 17 d6 13 10 11 10 11 0f 31 d4 } //1
		$a_01_1 = {47 00 65 00 74 00 4d 00 65 00 74 00 68 00 6f 00 64 00 00 11 44 00 65 00 6c 00 65 00 74 00 65 00 4d 00 43 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}