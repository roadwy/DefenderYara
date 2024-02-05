
rule TrojanDropper_Win32_Zbot{
	meta:
		description = "TrojanDropper:Win32/Zbot,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {eb 09 8b 55 90 01 01 83 c2 01 89 55 90 01 01 83 7d 90 01 01 29 73 1e 8b 45 90 01 01 0f b6 4c 05 90 01 01 85 c9 74 10 8b 55 90 01 01 81 c2 c9 02 00 00 8b 45 90 01 01 88 54 05 90 01 01 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}