
rule TrojanDownloader_Win32_Obitel_B{
	meta:
		description = "TrojanDownloader:Win32/Obitel.B,SIGNATURE_TYPE_PEHSTR,ffffff83 00 ffffff83 00 06 00 00 64 00 "
		
	strings :
		$a_01_0 = {80 f9 41 7c 08 80 f9 5a 7f 03 80 c1 20 8b da 0f a4 fa 0f 33 ed 0f be c1 0b ea c1 eb 11 c1 e7 0f 99 0b df 33 d8 33 ea 46 8a 0e 8b fb 8b d5 84 c9 75 ce } //0a 00 
		$a_01_1 = {66 69 78 61 73 65 72 76 65 72 2e 72 75 } //0a 00 
		$a_01_2 = {6c 64 72 2f 67 61 74 65 2e 70 68 70 } //0a 00 
		$a_01_3 = {73 66 63 5f 6f 73 2e 64 6c 6c } //01 00 
		$a_01_4 = {5c 75 73 65 72 69 6e 69 2e 65 78 65 } //01 00 
		$a_01_5 = {5c 75 73 65 72 69 6e 69 74 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}