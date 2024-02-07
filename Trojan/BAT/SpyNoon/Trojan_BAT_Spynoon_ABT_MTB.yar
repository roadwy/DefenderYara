
rule Trojan_BAT_Spynoon_ABT_MTB{
	meta:
		description = "Trojan:BAT/Spynoon.ABT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 07 00 00 05 00 "
		
	strings :
		$a_03_0 = {2b 2c 17 8d 09 00 00 01 25 16 72 d3 01 00 70 28 90 01 01 00 00 06 72 90 01 01 02 00 70 28 90 01 01 00 00 06 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 28 90 01 01 00 00 06 a2 90 00 } //05 00 
		$a_01_1 = {00 00 0f 00 28 50 00 00 0a 0b 07 06 58 03 06 91 52 00 00 06 17 58 0a 06 03 8e 69 fe 04 0c 08 2d df } //01 00 
		$a_01_2 = {57 65 62 43 6c 69 65 6e 74 } //01 00  WebClient
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_4 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //01 00  DownloadString
		$a_01_5 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //01 00  VirtualAlloc
		$a_01_6 = {48 74 6d 6c 44 65 63 6f 64 65 } //00 00  HtmlDecode
	condition:
		any of ($a_*)
 
}