
rule TrojanDownloader_Win32_Pipsek_B{
	meta:
		description = "TrojanDownloader:Win32/Pipsek.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 00 dd 6d 00 ff d7 4e 75 ec 6a 00 ff 15 90 01 04 5f 5e cc 90 00 } //01 00 
		$a_01_1 = {b0 6c 88 44 24 1b 88 44 24 23 88 44 24 0a 88 44 24 10 88 44 24 11 b0 4f 53 b1 6f } //01 00 
		$a_01_2 = {25 73 3f 6d 61 63 3d 25 73 26 76 65 72 3d 25 73 } //01 00  %s?mac=%s&ver=%s
		$a_01_3 = {56 56 56 56 56 56 00 00 43 43 43 43 43 43 00 00 5c 54 61 73 6b 73 00 } //00 00 
	condition:
		any of ($a_*)
 
}