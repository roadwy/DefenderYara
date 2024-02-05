
rule TrojanDownloader_Win32_Bancos_FM{
	meta:
		description = "TrojanDownloader:Win32/Bancos.FM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 74 74 70 3a 2f 2f 64 6c 2e 64 72 6f 70 62 6f 78 2e 63 6f 6d 2f 75 2f 90 0f 08 00 2f 61 70 73 65 74 61 2e 70 70 73 90 00 } //01 00 
		$a_01_1 = {63 61 62 61 6c 6c 6f 31 } //01 00 
		$a_01_2 = {73 65 72 74 75 70 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}