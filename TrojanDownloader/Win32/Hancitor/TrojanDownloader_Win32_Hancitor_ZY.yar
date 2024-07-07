
rule TrojanDownloader_Win32_Hancitor_ZY{
	meta:
		description = "TrojanDownloader:Win32/Hancitor.ZY,SIGNATURE_TYPE_PEHSTR_EXT,6f 00 6f 00 03 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //1
		$a_01_1 = {6e 63 64 72 6c 65 62 } //10 ncdrleb
		$a_01_2 = {b8 01 00 00 00 c1 e0 00 8b 4d 08 0f be 14 01 83 fa 3a 75 35 8b 45 fc 0f be 08 85 c9 74 2b 8b 55 fc 0f be 02 b9 01 00 00 00 6b d1 00 8b 4d 08 0f be 14 11 3b c2 75 07 b8 01 00 00 00 eb 0d 8b 45 fc 83 c0 01 89 45 fc eb cb } //100
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*10+(#a_01_2  & 1)*100) >=111
 
}