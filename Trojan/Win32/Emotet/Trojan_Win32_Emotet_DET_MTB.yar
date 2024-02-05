
rule Trojan_Win32_Emotet_DET_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DET!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b6 4d f3 0f b6 07 03 c1 99 8b ce f7 f9 8b 45 e8 8a 4c 15 00 30 08 90 02 03 83 bd 90 01 04 00 89 45 e8 90 00 } //01 00 
		$a_81_1 = {7a 39 57 68 48 6d 70 75 68 4d 58 67 78 67 63 62 46 49 62 4d 78 5a 44 36 7a 78 57 75 79 5a 6c } //00 00 
	condition:
		any of ($a_*)
 
}