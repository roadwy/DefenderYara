
rule TrojanDownloader_Win32_Obitel_gen_B{
	meta:
		description = "TrojanDownloader:Win32/Obitel.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {7f 03 80 c1 20 8b da 0f a4 fa 0f 33 ed 0f be c1 0b ea c1 eb 11 c1 e7 0f 99 } //01 00 
		$a_01_1 = {eb 11 8b 5d fc 0f be d2 c1 c3 0d 33 da 47 8a 17 89 5d fc 84 d2 75 eb } //01 00 
		$a_03_2 = {6a 01 68 87 07 00 00 ff 15 90 01 02 40 00 eb f1 90 00 } //01 00 
		$a_00_3 = {51 75 65 75 65 55 73 65 72 41 50 43 } //00 00 
	condition:
		any of ($a_*)
 
}