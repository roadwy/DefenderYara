
rule Trojan_Win64_Ceilscour_YAA_MTB{
	meta:
		description = "Trojan:Win64/Ceilscour.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 4c 24 68 33 c1 48 8d 0d ?? ?? ?? ?? 48 8b 54 24 60 48 2b d1 48 8b ca 0f b6 c9 81 e1 80 00 00 00 33 c1 48 8b 4c 24 60 88 01 48 63 44 24 20 48 8b 4c 24 60 48 03 c8 48 8b c1 48 89 44 24 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}