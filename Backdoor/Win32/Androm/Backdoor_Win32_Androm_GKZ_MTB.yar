
rule Backdoor_Win32_Androm_GKZ_MTB{
	meta:
		description = "Backdoor:Win32/Androm.GKZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0f be 11 33 15 90 01 04 a1 90 01 04 03 85 90 01 04 88 10 68 90 01 04 6a 17 e8 90 01 04 83 c4 08 8b 0d 90 01 04 03 8d 90 01 04 0f be 11 2b 15 90 01 04 a1 90 01 04 03 85 90 01 04 88 10 90 00 } //01 00 
		$a_80_1 = {4d 6f 72 65 67 } //Moreg  01 00 
		$a_80_2 = {5a 61 70 61 7a } //Zapaz  01 00 
		$a_01_3 = {40 2e 72 6f 70 66 } //00 00 
	condition:
		any of ($a_*)
 
}