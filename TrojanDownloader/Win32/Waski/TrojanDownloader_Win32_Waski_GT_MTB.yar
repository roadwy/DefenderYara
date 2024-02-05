
rule TrojanDownloader_Win32_Waski_GT_MTB{
	meta:
		description = "TrojanDownloader:Win32/Waski.GT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {33 00 2b f0 8b 55 f8 c1 c2 16 52 c3 2b d3 8b ff 8b 16 3b d7 72 9e } //01 00 
		$a_80_1 = {53 61 6a 6c 69 6c 65 73 70 69 6c 76 69 } //Sajlilespilvi  00 00 
	condition:
		any of ($a_*)
 
}