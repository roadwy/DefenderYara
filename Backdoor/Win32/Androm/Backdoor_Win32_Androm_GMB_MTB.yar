
rule Backdoor_Win32_Androm_GMB_MTB{
	meta:
		description = "Backdoor:Win32/Androm.GMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {83 ec 14 57 6a 06 6a 01 8b f9 6a 02 ff 15 } //05 00 
		$a_03_1 = {8b f0 66 c7 44 24 90 01 01 02 00 ff 15 90 01 04 66 89 44 24 16 8b 46 0c 68 90 01 04 8b 08 8b 44 24 14 50 8b 11 89 54 24 20 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}