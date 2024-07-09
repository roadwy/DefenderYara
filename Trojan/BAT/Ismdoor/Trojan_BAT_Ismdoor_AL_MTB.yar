
rule Trojan_BAT_Ismdoor_AL_MTB{
	meta:
		description = "Trojan:BAT/Ismdoor.AL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {03 17 da 17 d6 8d ?? 00 00 01 0b 02 07 16 03 28 ?? 00 00 0a 00 07 0a 2b 00 06 2a } //10
		$a_02_1 = {02 02 02 1f 3c 6a d6 28 ?? 00 00 0a 28 ?? 00 00 0a 6a d6 20 88 00 00 00 6a d6 28 ?? 00 00 0a 28 ?? 00 00 0a 6a d6 1f 18 6a d6 28 ?? 00 00 0a 1f 10 28 ?? 00 00 06 0b } //10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}