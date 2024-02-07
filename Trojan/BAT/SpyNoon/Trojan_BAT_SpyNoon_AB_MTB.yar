
rule Trojan_BAT_SpyNoon_AB_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 1a 00 08 00 00 0a 00 "
		
	strings :
		$a_03_0 = {7e 01 00 00 04 02 6f 90 01 01 00 00 0a 0a 06 72 90 01 01 00 00 70 28 90 00 } //0a 00 
		$a_01_1 = {0f 00 28 1b 00 00 0a 0a 06 03 58 04 52 } //01 00 
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //01 00  DownloadString
		$a_01_3 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00  VirtualProtect
		$a_01_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_5 = {57 65 62 43 6c 69 65 6e 74 } //01 00  WebClient
		$a_01_6 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_7 = {48 74 6d 6c 44 65 63 6f 64 65 } //00 00  HtmlDecode
	condition:
		any of ($a_*)
 
}