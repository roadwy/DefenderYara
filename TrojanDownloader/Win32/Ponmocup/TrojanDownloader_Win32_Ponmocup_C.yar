
rule TrojanDownloader_Win32_Ponmocup_C{
	meta:
		description = "TrojanDownloader:Win32/Ponmocup.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {66 83 f9 07 73 28 0f b6 c0 8b d0 d1 ea c1 e0 07 33 d0 33 c0 8a c2 88 45 b7 0f b7 f1 33 d2 8a 14 b5 90 01 04 03 d0 88 54 35 cc 41 eb cf 90 00 } //01 00 
		$a_01_1 = {75 f9 2b c2 8d bd fc fd ff ff 4f 8a 4f 01 47 84 c9 75 f8 8b c8 8b f2 c1 e9 02 f3 a5 8b c8 83 e1 03 f3 a4 8d } //01 00 
		$a_03_2 = {66 3d 39 00 73 20 81 c1 87 a9 f3 47 89 8d 9c fe ff ff 0f b7 f0 33 d2 8a 96 90 01 04 2b d1 88 54 35 a8 40 eb d4 90 00 } //01 00 
		$a_03_3 = {3a ca 7d 27 05 d7 3a ff ff 89 85 c8 fe ff ff 0f be f1 33 db 8a 1c 75 90 01 04 33 d8 88 5c 35 d4 fe c1 88 8d cf fe ff ff eb d5 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}