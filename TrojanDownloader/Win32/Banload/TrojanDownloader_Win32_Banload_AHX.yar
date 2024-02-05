
rule TrojanDownloader_Win32_Banload_AHX{
	meta:
		description = "TrojanDownloader:Win32/Banload.AHX,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {4f 00 70 00 66 00 53 00 4b 00 37 00 39 00 6c 00 50 00 74 00 39 00 58 00 52 00 4b 00 48 00 58 00 54 00 36 00 34 00 } //01 00 
		$a_01_1 = {85 db 7c 5f 8b 45 f0 c1 e0 06 03 d8 89 5d f0 83 c7 06 83 ff 08 7c 42 83 ef 08 8b cf 8b 5d f0 d3 eb 8b cf b8 01 00 00 00 d3 e0 8b c8 8b 45 f0 99 f7 f9 89 55 f0 b9 00 01 00 00 8b c3 99 f7 f9 } //00 00 
	condition:
		any of ($a_*)
 
}