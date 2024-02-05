
rule Trojan_Win32_Gozi_YAA_MTB{
	meta:
		description = "Trojan:Win32/Gozi.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 c1 8b 4e 70 89 86 dc 00 00 00 8b 86 90 01 04 2b 05 90 01 04 35 90 01 04 0f af 86 e8 00 00 00 89 86 e8 00 00 00 8b 46 38 03 46 58 83 f0 4e 01 46 1c 0f b6 c3 0f af d0 8b 86 9c 00 00 00 88 14 01 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}