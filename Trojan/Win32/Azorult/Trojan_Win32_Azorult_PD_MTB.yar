
rule Trojan_Win32_Azorult_PD_MTB{
	meta:
		description = "Trojan:Win32/Azorult.PD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 02 00 00 14 00 "
		
	strings :
		$a_02_0 = {8b c7 8d b5 90 01 02 ff ff 83 e0 03 03 f7 83 c7 06 8a 54 05 f8 8d 04 0e 30 16 83 e0 03 30 56 04 8a 4c 05 f8 8d 43 ff 30 4e 01 83 e0 03 30 4e 05 8b 8d 90 01 02 ff ff 8a 44 05 f8 30 46 02 8b c3 83 e0 03 83 c3 06 8a 44 05 f8 30 46 03 81 ff 90 01 02 00 00 72 90 00 } //01 00 
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //00 00 
	condition:
		any of ($a_*)
 
}