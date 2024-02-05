
rule TrojanDownloader_Win32_Nuyap_A{
	meta:
		description = "TrojanDownloader:Win32/Nuyap.A,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {c6 44 24 14 55 c6 44 24 15 52 c6 44 24 16 4c c6 44 24 17 44 } //01 00 
		$a_01_1 = {8a 1c 08 80 f3 90 88 1c 08 40 3b c2 7c f2 } //00 00 
	condition:
		any of ($a_*)
 
}