
rule TrojanDownloader_Win32_Phidagem_gen_A{
	meta:
		description = "TrojanDownloader:Win32/Phidagem.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {40 00 6a 68 8d 90 01 06 ff 15 90 01 04 6a 70 8d 90 01 0c 6a 3f 8d 90 01 0c 6a 69 8d 90 01 0c 6a 6d 8d 90 01 0c 6a 61 8d 90 01 0c 6a 67 8d 90 01 0c 6a 65 8d 90 01 0c 6a 69 8d 90 01 0c 6a 64 8d 90 01 0c 6a 3d 90 00 } //01 00 
		$a_03_1 = {40 00 6a 3b 8d 90 01 06 ff 15 90 01 04 6a 57 8d 90 01 0c 6a 4f 8d 90 01 0c 6a 57 8d 90 01 0c 6a 36 8d 90 01 0c 6a 34 8d 90 01 0c 6a 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}