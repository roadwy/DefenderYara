
rule TrojanSpy_Win32_Banker_AEJ{
	meta:
		description = "TrojanSpy:Win32/Banker.AEJ,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 61 73 6b 6b 69 6c 6c 00 00 00 00 ff ff ff ff } //01 00 
		$a_01_1 = {06 00 00 00 63 6d 64 20 2f 6b 00 00 ff ff ff ff } //01 00 
		$a_01_2 = {13 00 00 00 2f 49 4d 20 69 65 78 70 6c 6f 72 65 2e 65 78 65 20 2f 46 00 } //01 00 
		$a_01_3 = {12 00 00 00 2f 49 4d 20 66 69 72 65 66 6f 78 2e 65 78 65 20 2f 46 00 00 } //01 00 
		$a_03_4 = {41 75 74 6f 43 6f 6e 66 69 67 55 52 4c 00 00 00 ff ff ff ff 90 01 01 00 00 00 68 74 74 70 3a 2f 2f 90 00 } //01 00 
		$a_03_5 = {0d 80 00 00 00 50 6a ec a1 90 01 02 44 00 53 e8 90 01 02 fb ff 68 88 13 00 00 e8 90 01 02 fb ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}