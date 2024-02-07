
rule TrojanProxy_Win32_Koobface_gen_I{
	meta:
		description = "TrojanProxy:Win32/Koobface.gen!I,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 09 00 00 01 00 "
		
	strings :
		$a_00_0 = {70 6f 73 74 3d 74 72 75 65 26 70 61 74 68 3d 63 61 70 74 63 68 61 26 61 3d 71 75 65 72 79 26 62 3d 25 73 26 69 64 3d 25 73 } //01 00  post=true&path=captcha&a=query&b=%s&id=%s
		$a_00_1 = {3f 61 63 74 69 6f 6e 3d 62 73 26 76 3d 32 30 26 61 3d 6e 61 6d 65 73 } //01 00  ?action=bs&v=20&a=names
		$a_00_2 = {68 74 74 70 3a 2f 2f 6e 65 77 73 2e 67 6f 6f 67 6c 65 2e 63 6f 6d 2f 6e 65 77 73 3f 6e 65 64 3d 75 73 26 6f 75 74 70 75 74 3d 72 73 73 } //01 00  http://news.google.com/news?ned=us&output=rss
		$a_00_3 = {61 63 63 6f 75 6e 74 73 2f 43 61 70 74 63 68 61 } //01 00  accounts/Captcha
		$a_00_4 = {23 42 4c 41 43 4b 4c 41 42 45 4c } //01 00  #BLACKLABEL
		$a_03_5 = {85 c0 7e 28 01 44 90 01 02 83 bc 24 14 90 01 04 74 0d 8b 8c 24 90 01 04 85 c9 74 02 01 01 6a 00 68 00 04 00 00 ff 74 90 01 02 eb cb 90 00 } //02 00 
		$a_01_6 = {74 16 8a 08 80 f9 30 74 3a 80 f9 31 74 0a 80 f9 32 74 30 80 f9 33 74 0f } //02 00 
		$a_03_7 = {6a 7c 50 c6 90 01 03 ff 15 90 01 04 59 85 c0 59 90 00 } //01 00 
		$a_03_8 = {40 00 33 c0 83 90 01 03 0f 95 c0 48 83 e0 90 01 01 83 c0 90 01 01 69 c0 90 01 04 50 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}