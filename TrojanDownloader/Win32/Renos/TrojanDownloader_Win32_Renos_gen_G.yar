
rule TrojanDownloader_Win32_Renos_gen_G{
	meta:
		description = "TrojanDownloader:Win32/Renos.gen!G,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 80 ee 36 00 ff 15 } //01 00 
		$a_01_1 = {83 c4 30 46 81 fe 00 01 00 00 } //01 00 
		$a_01_2 = {25 ff 00 00 00 8a 4c 04 18 8d 44 04 18 } //00 00 
	condition:
		any of ($a_*)
 
}