
rule TrojanDownloader_Win32_Dofoil_R{
	meta:
		description = "TrojanDownloader:Win32/Dofoil.R,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {81 c7 04 05 00 00 b8 43 6b 7e 0a ab b8 5a 3f 23 65 ab } //01 00 
		$a_03_1 = {b0 68 aa 8b 45 90 01 01 ab b0 c3 aa 90 00 } //01 00 
		$a_01_2 = {81 c7 00 12 00 00 66 c7 07 57 6f 66 c7 47 02 72 6b } //00 00 
	condition:
		any of ($a_*)
 
}