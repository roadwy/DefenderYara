
rule TrojanDownloader_Win32_Tyqui_B{
	meta:
		description = "TrojanDownloader:Win32/Tyqui.B,SIGNATURE_TYPE_PEHSTR_EXT,07 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {3c 00 2f 00 46 00 49 00 4c 00 45 00 3e 00 } //01 00 
		$a_01_1 = {3c 00 2f 00 55 00 52 00 4c 00 3e 00 } //01 00 
		$a_01_2 = {49 00 66 00 20 00 45 00 78 00 69 00 73 00 74 00 } //01 00 
		$a_01_3 = {73 00 79 00 73 00 74 00 65 00 6d 00 64 00 72 00 69 00 76 00 65 00 } //03 00 
		$a_01_4 = {bd 78 ff ff ff 00 0f 84 4d 05 00 00 8d 55 8c 8d 4d bc } //03 00 
		$a_01_5 = {c7 45 94 20 1b 40 00 c7 45 8c 08 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}