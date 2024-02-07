
rule Backdoor_Win32_Androm_GJO_MTB{
	meta:
		description = "Backdoor:Win32/Androm.GJO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {55 8b ec 83 ec 20 b8 90 01 04 81 75 90 01 01 ff 00 ff 00 83 f8 07 90 01 02 29 d2 83 6d fc 77 66 ba 61 00 3b 55 f8 90 01 02 c7 45 90 01 01 40 00 00 00 b9 90 01 04 83 6d f4 04 83 f9 00 90 01 02 8b 45 ec 8d 45 f4 81 f8 aa 09 00 00 90 00 } //01 00 
		$a_80_1 = {6d 61 78 20 45 64 69 74 69 6f 6e 2e 65 78 65 } //max Edition.exe  01 00 
		$a_01_2 = {2e 72 6f 70 66 } //00 00  .ropf
	condition:
		any of ($a_*)
 
}