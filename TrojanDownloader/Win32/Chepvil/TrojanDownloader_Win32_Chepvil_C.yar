
rule TrojanDownloader_Win32_Chepvil_C{
	meta:
		description = "TrojanDownloader:Win32/Chepvil.C,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {6a 00 59 8b 55 08 28 58 eb 07 8b ff d3 c9 90 33 c1 8a 0a 42 0a c9 75 f4 c9 c2 04 00 f9 83 c4 } //00 00 
	condition:
		any of ($a_*)
 
}