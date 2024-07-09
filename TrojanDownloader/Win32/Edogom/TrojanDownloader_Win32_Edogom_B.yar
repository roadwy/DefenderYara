
rule TrojanDownloader_Win32_Edogom_B{
	meta:
		description = "TrojanDownloader:Win32/Edogom.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {81 7d fc de 00 00 00 76 20 33 c0 8b c8 8b 85 ?? ?? ff ff 03 c8 87 d9 33 c0 50 59 50 51 ff d3 } //1
		$a_03_1 = {81 fa be 2f 00 00 73 18 8d 85 ?? ?? ff ff 50 8d 8d ?? ?? ff ff 51 e8 ?? ?? ?? ?? 83 c4 08 eb 24 } //1
		$a_01_2 = {04 12 2b 34 37 55 47 4a 28 6b 43 23 32 4c } //1 ሄ㐫唷䩇欨⍃䰲
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}