
rule TrojanDownloader_Win32_Edogom_B{
	meta:
		description = "TrojanDownloader:Win32/Edogom.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {81 7d fc de 00 00 00 76 20 33 c0 8b c8 8b 85 90 01 02 ff ff 03 c8 87 d9 33 c0 50 59 50 51 ff d3 90 00 } //01 00 
		$a_03_1 = {81 fa be 2f 00 00 73 18 8d 85 90 01 02 ff ff 50 8d 8d 90 01 02 ff ff 51 e8 90 01 04 83 c4 08 eb 24 90 00 } //01 00 
		$a_01_2 = {04 12 2b 34 37 55 47 4a 28 6b 43 23 32 4c } //00 00  ሄ㐫唷䩇欨⍃䰲
	condition:
		any of ($a_*)
 
}