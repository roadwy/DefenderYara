
rule TrojanDownloader_Win32_Bancos_EH{
	meta:
		description = "TrojanDownloader:Win32/Bancos.EH,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 79 73 74 65 61 6d 5c 72 65 61 63 74 69 6f 6e 5c } //01 00 
		$a_02_1 = {74 61 73 6b 6b 69 6c 6c 90 02 04 20 2d 66 20 2d 69 6d 20 90 02 06 2e 65 78 65 90 00 } //01 00 
		$a_00_2 = {4d 75 54 65 78 58 78 32 30 31 30 } //00 00 
	condition:
		any of ($a_*)
 
}