
rule Trojan_Win32_Amadey_PTM_MTB{
	meta:
		description = "Trojan:Win32/Amadey.PTM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {30 04 3e 46 3b f3 7c f3 } //01 00 
		$a_03_1 = {8b 0d e0 46 bd 02 89 4c 24 0c b8 31 a2 00 00 01 44 24 0c 8b 54 24 0c 8a 04 32 8b 0d 90 01 04 88 04 31 81 3d 90 01 04 ab 05 00 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}