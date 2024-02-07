
rule PWS_Win32_Lolyda_J{
	meta:
		description = "PWS:Win32/Lolyda.J,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0a 00 06 00 00 04 00 "
		
	strings :
		$a_03_0 = {c6 45 ff e9 ff 15 90 01 02 00 10 8b 75 0c 8b d8 8d 45 d0 90 00 } //04 00 
		$a_03_1 = {74 71 83 7d f8 01 75 6b 8d 45 f8 50 8d 46 08 6a 04 50 8b 06 40 50 53 ff d7 85 c0 74 56 83 7d f8 04 75 50 8d 45 f4 8b 3d 90 01 02 00 10 50 8d 45 ff 6a 01 90 00 } //01 00 
		$a_00_2 = {3f 73 65 72 76 65 72 3d 25 73 26 67 61 6d 65 69 64 3d 25 73 26 70 61 73 73 3d 25 73 26 70 69 6e 3d 25 73 26 77 75 70 69 6e 3d 25 73 26 72 6f 6c 65 3d 25 73 26 65 71 75 3d } //01 00  ?server=%s&gameid=%s&pass=%s&pin=%s&wupin=%s&role=%s&equ=
		$a_01_3 = {46 6f 72 74 68 67 6f 6e 65 72 } //01 00  Forthgoner
		$a_00_4 = {2e 63 6e 2f 76 65 72 69 66 79 2f 70 6f 73 74 6c 79 2e 61 73 70 } //01 00  .cn/verify/postly.asp
		$a_00_5 = {5c 75 73 65 72 64 61 74 61 5c 63 75 72 72 65 6e 74 73 65 72 76 65 72 2e 69 6e 69 } //00 00  \userdata\currentserver.ini
	condition:
		any of ($a_*)
 
}