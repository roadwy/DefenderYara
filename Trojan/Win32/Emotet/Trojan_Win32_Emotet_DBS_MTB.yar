
rule Trojan_Win32_Emotet_DBS_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DBS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 05 00 "
		
	strings :
		$a_02_0 = {0f b6 07 0f b6 cb 03 c1 99 8b ce f7 f9 8b 45 8c 8a 4c 15 90 01 01 30 08 40 83 bd 90 01 04 00 89 45 8c 0f 85 90 00 } //02 00 
		$a_00_1 = {44 4f 4b 55 44 4f } //01 00 
		$a_81_2 = {65 72 7a 47 47 57 47 34 74 67 32 7a 79 7a 65 } //01 00 
		$a_81_3 = {61 7a 67 61 34 61 67 33 67 33 71 67 } //01 00 
		$a_81_4 = {43 72 79 70 74 41 63 71 75 69 72 65 43 6f 6e 74 65 78 74 41 } //00 00 
	condition:
		any of ($a_*)
 
}