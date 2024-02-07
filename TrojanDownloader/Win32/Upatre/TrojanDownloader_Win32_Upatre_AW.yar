
rule TrojanDownloader_Win32_Upatre_AW{
	meta:
		description = "TrojanDownloader:Win32/Upatre.AW,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 05 00 "
		
	strings :
		$a_01_0 = {33 c1 89 06 03 f2 59 47 } //01 00 
		$a_80_1 = {00 61 70 70 6c 69 63 61 74 69 6f 6e 2f 2a 00 } //  01 00 
		$a_80_2 = {00 74 65 78 74 2f 2a 00 } //  01 00 
		$a_00_3 = {52 74 6c 44 65 63 6f 6d 70 72 65 73 73 42 75 66 66 65 72 } //01 00  RtlDecompressBuffer
		$a_00_4 = {25 73 25 73 00 25 73 5c 25 73 00 6f 70 65 6e } //01 00 
		$a_00_5 = {63 68 65 63 6b 69 70 2e 64 79 6e 64 6e 73 2e 6f 72 67 } //00 00  checkip.dyndns.org
		$a_00_6 = {5d 04 00 00 eb 2c 03 } //80 5c 
	condition:
		any of ($a_*)
 
}