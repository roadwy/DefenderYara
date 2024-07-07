
rule TrojanDownloader_Win32_Upatre_BV{
	meta:
		description = "TrojanDownloader:Win32/Upatre.BV,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 15 a4 39 60 00 8b c1 25 ff 0f 00 00 66 8b 84 42 84 00 00 00 0f b7 c0 8b d1 c1 ea 05 33 d0 f7 c2 80 7f 00 00 75 0e 83 e0 7f 74 09 b8 01 00 00 00 5d } //1
		$a_01_1 = {48 4f 4c 59 20 53 48 49 54 20 4d 59 0a 47 41 52 44 45 4e 27 53 20 4f 4e 20 46 49 52 45 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}