
rule TrojanSpy_Win32_Banker_YX{
	meta:
		description = "TrojanSpy:Win32/Banker.YX,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_02_0 = {67 62 70 00 90 09 08 00 ff ff ff ff 03 00 00 00 90 00 } //01 00 
		$a_02_1 = {67 62 69 65 00 90 09 08 00 ff ff ff ff 04 00 00 00 90 00 } //01 00 
		$a_02_2 = {5c 3f 3f 5c 00 90 09 08 00 ff ff ff ff 04 00 00 00 90 00 } //01 00 
		$a_02_3 = {73 63 70 00 90 09 08 00 ff ff ff ff 03 00 00 00 90 00 } //01 00 
		$a_02_4 = {73 73 68 69 62 00 90 09 08 00 ff ff ff ff 05 00 00 00 90 00 } //01 00 
		$a_02_5 = {ff 03 c7 b9 ff 00 00 00 99 f7 f9 8b da 3b 75 90 01 01 7d 03 46 eb 05 be 01 00 00 00 8b 45 90 01 01 90 03 03 00 90 01 10 0f b6 44 30 ff 33 d8 8d 45 90 01 01 50 89 5d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}