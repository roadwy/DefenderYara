
rule Trojan_BAT_Shelm_ASE_MTB{
	meta:
		description = "Trojan:BAT/Shelm.ASE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 13 16 2b 15 07 11 16 07 11 16 91 20 dc 00 00 00 61 d2 9c 11 16 17 58 13 16 11 16 07 8e 69 32 e4 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Shelm_ASE_MTB_2{
	meta:
		description = "Trojan:BAT/Shelm.ASE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {7e 18 00 00 0a 13 05 7e 18 00 00 0a 13 06 11 04 28 ?? ?? ?? 06 12 06 7e 18 00 00 0a 7e 18 00 00 0a 11 05 12 01 18 16 1a 28 ?? ?? ?? 0a 26 06 16 11 06 06 8e 69 28 ?? ?? ?? 0a 7e 18 00 00 0a 13 07 11 04 08 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}