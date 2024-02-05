
rule Backdoor_Win32_Androm_GCS_MTB{
	meta:
		description = "Backdoor:Win32/Androm.GCS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b 45 f4 83 c0 01 89 45 f4 81 7d f4 ff 00 00 00 7d 0b 8b 4d f0 33 4d f4 89 4d f0 eb 90 01 01 8b 55 f0 33 55 ec 83 f2 0f 8b 45 08 03 45 fc 88 10 90 00 } //01 00 
		$a_01_1 = {33 43 72 65 61 74 65 4d 75 74 65 78 } //00 00 
	condition:
		any of ($a_*)
 
}