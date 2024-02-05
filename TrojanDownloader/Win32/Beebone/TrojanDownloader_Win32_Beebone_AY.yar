
rule TrojanDownloader_Win32_Beebone_AY{
	meta:
		description = "TrojanDownloader:Win32/Beebone.AY,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {5a 75 74 75 67 69 6c } //01 00 
		$a_01_1 = {72 65 63 65 69 76 65 64 6e 65 73 73 } //01 00 
		$a_01_2 = {63 61 62 69 6e 65 74 77 6f 72 6b } //02 00 
		$a_01_3 = {81 69 e2 93 09 c1 b0 40 be f7 ab 48 48 35 c4 b7 } //00 00 
	condition:
		any of ($a_*)
 
}