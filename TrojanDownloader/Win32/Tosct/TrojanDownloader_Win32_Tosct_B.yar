
rule TrojanDownloader_Win32_Tosct_B{
	meta:
		description = "TrojanDownloader:Win32/Tosct.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 48 01 40 84 c9 75 f8 8a 08 80 f9 5c 74 0d 3a ca 74 09 8a 48 ff 48 80 f9 5c 75 f3 } //01 00 
		$a_03_1 = {c6 04 28 00 8a 45 00 83 c4 0c 3c 73 0f 84 90 01 01 01 00 00 3c 53 0f 84 90 01 01 01 00 00 3c 64 0f 84 90 01 01 01 00 00 3c 44 0f 84 90 01 01 01 00 00 3c 72 74 90 01 01 3c 52 74 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}