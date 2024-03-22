
rule Backdoor_Win32_Androm_GXB_MTB{
	meta:
		description = "Backdoor:Win32/Androm.GXB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b f0 8b 44 24 24 50 ff 15 90 01 04 8b 4c 24 28 8b f8 51 66 c7 44 24 14 02 00 ff d6 66 89 44 24 12 8b 57 0c 68 90 01 04 53 8b 02 8b 08 89 4c 24 1c ff 15 90 01 04 8b 4d 08 8d 54 24 10 6a 10 52 51 ff d0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}