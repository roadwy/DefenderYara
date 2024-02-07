
rule TrojanDownloader_Win32_Gelode_A{
	meta:
		description = "TrojanDownloader:Win32/Gelode.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {04 30 88 44 3e ff 8a 41 fe } //01 00 
		$a_01_1 = {30 37 33 31 31 30 31 31 36 31 30 31 31 31 34 31 31 30 31 30 31 31 31 36 30 38 32 31 30 31 30 39 37 31 30 30 30 37 30 31 30 35 31 30 38 31 30 31 } //00 00  073110116101114110101116082101097100070105108101
	condition:
		any of ($a_*)
 
}