
rule Backdoor_Win32_Androm_GMX_MTB{
	meta:
		description = "Backdoor:Win32/Androm.GMX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b f0 8b 44 24 90 01 01 50 ff 15 90 01 04 8b 4c 24 90 01 01 8b f8 51 66 c7 44 24 90 01 01 02 00 ff d6 66 89 44 24 90 01 01 8b 57 90 01 01 68 90 01 04 53 8b 02 8b 08 89 4c 24 90 01 01 ff d5 8b 74 24 90 01 01 8d 54 24 90 01 01 6a 10 52 8b 4e 90 01 01 51 ff d0 83 f8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}