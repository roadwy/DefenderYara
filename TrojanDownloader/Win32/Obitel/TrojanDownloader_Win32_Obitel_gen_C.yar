
rule TrojanDownloader_Win32_Obitel_gen_C{
	meta:
		description = "TrojanDownloader:Win32/Obitel.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b 07 3d 68 74 74 70 75 } //01 00 
		$a_01_1 = {32 f2 88 33 43 } //01 00 
		$a_01_2 = {8a 21 32 e0 88 21 } //01 00 
		$a_01_3 = {8a 02 83 f0 00 3d cc 00 00 00 75 } //00 00 
	condition:
		any of ($a_*)
 
}