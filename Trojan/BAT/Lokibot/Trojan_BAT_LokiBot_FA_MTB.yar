
rule Trojan_BAT_LokiBot_FA_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.FA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 65 64 6f 6d 20 53 4f 44 20 6e 69 20 6e 75 72 20 65 62 20 74 6f 6e 6e 61 63 20 6d 61 72 67 6f 72 70 20 73 69 68 54 21 } //01 00  .edom SOD ni nur eb tonnac margorp sihT!
		$a_01_1 = {48 74 74 70 57 65 62 52 65 71 75 65 73 74 } //01 00  HttpWebRequest
		$a_01_2 = {47 65 74 54 79 70 65 73 } //01 00  GetTypes
		$a_01_3 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //01 00  MemoryStream
		$a_01_4 = {58 00 72 00 64 00 65 00 68 00 64 00 6e 00 77 00 6f 00 6e 00 6f 00 64 00 71 00 68 00 61 00 76 00 63 00 69 00 } //00 00  Xrdehdnwonodqhavci
	condition:
		any of ($a_*)
 
}