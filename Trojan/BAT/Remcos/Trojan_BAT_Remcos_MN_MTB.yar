
rule Trojan_BAT_Remcos_MN_MTB{
	meta:
		description = "Trojan:BAT/Remcos.MN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 07 00 00 0a 00 "
		
	strings :
		$a_01_0 = {57 95 02 20 09 0a 00 00 00 00 00 00 00 00 00 00 01 00 00 00 36 00 00 00 08 00 00 00 73 00 00 00 25 } //01 00 
		$a_01_1 = {24 64 30 32 36 36 39 35 37 2d 63 31 63 38 2d 34 30 61 36 2d 61 31 38 31 2d 32 33 63 32 38 36 30 36 66 32 33 66 } //01 00  $d0266957-c1c8-40a6-a181-23c28606f23f
		$a_01_2 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //01 00  MemoryStream
		$a_01_3 = {48 74 74 70 57 65 62 52 65 73 70 6f 6e 73 65 } //01 00  HttpWebResponse
		$a_01_4 = {48 74 74 70 57 65 62 52 65 71 75 65 73 74 } //01 00  HttpWebRequest
		$a_01_5 = {47 65 74 44 6f 6d 61 69 6e } //01 00  GetDomain
		$a_01_6 = {47 65 74 42 79 74 65 73 } //00 00  GetBytes
	condition:
		any of ($a_*)
 
}