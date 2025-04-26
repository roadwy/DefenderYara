
rule Trojan_BAT_Agensla_GG_MTB{
	meta:
		description = "Trojan:BAT/Agensla.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {02 09 02 8e 69 5d 02 09 02 8e 69 5d 91 07 09 07 8e 69 5d 91 61 02 09 17 d6 02 8e 69 5d 91 da [0-05] d6 [0-05] 5d b4 9c 09 15 d6 0d 09 16 2f cb } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Agensla_GG_MTB_2{
	meta:
		description = "Trojan:BAT/Agensla.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {2b 61 02 09 02 8e 69 5d 02 09 02 8e 69 5d 91 07 09 07 8e 69 5d 91 61 02 09 17 d6 02 8e 69 5d 91 da 20 ?? ?? ?? 00 28 ?? ?? ?? 06 28 ?? ?? ?? 0a d6 20 ?? ?? ?? 00 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 5d b4 9c 09 15 d6 0d 2b 1a } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}