
rule TrojanDropper_Win32_Cutwail_A{
	meta:
		description = "TrojanDropper:Win32/Cutwail.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8a 0f 80 f9 00 74 90 01 01 30 0b 90 02 04 48 74 90 01 01 43 47 eb 90 00 } //01 00 
		$a_02_1 = {83 ec 04 53 56 57 8b 4d 08 90 01 02 49 49 0f b6 09 89 4d fc 8b 7d 0c 56 ff 15 90 01 06 89 1f 83 c7 04 e8 90 01 04 56 53 ff 15 90 01 04 89 07 83 c7 04 e8 90 01 04 3c 00 75 ea 46 ff 4d fc 83 7d fc 00 75 cd 90 01 02 5f 5e 5b c9 c2 08 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}