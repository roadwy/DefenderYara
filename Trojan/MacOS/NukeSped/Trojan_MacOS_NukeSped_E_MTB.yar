
rule Trojan_MacOS_NukeSped_E_MTB{
	meta:
		description = "Trojan:MacOS/NukeSped.E!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {34 11 48 63 f6 8b b4 b5 e0 fe ff ff 31 b4 95 d0 fe ff ff 48 ff c2 48 39 d0 75 e4 } //02 00 
		$a_02_1 = {48 81 ec d8 00 00 00 49 89 d5 49 89 f7 49 89 fc 48 8b 05 3d 14 00 00 48 8b 00 48 89 45 d0 8b 0d 88 17 00 00 83 f9 ff 75 20 48 8d 3d 00 0e 00 00 48 8d b5 40 ff ff ff 90 01 05 31 c9 85 c0 0f 95 c1 89 0d 63 17 00 00 90 00 } //01 00 
		$a_00_2 = {71 6e 61 6c 79 74 69 63 61 2e 63 6f 6d 2f 77 70 2d 72 73 73 2e 70 68 70 } //01 00  qnalytica.com/wp-rss.php
		$a_00_3 = {42 61 72 62 65 71 75 65 3a 3a 7e 42 61 72 62 65 71 75 65 28 29 } //01 00  Barbeque::~Barbeque()
		$a_00_4 = {63 75 72 6c 5f 65 61 73 79 5f 67 65 74 69 6e 66 6f } //00 00  curl_easy_getinfo
		$a_00_5 = {5d 04 00 } //00 ae 
	condition:
		any of ($a_*)
 
}