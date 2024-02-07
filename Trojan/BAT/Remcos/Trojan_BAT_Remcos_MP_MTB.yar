
rule Trojan_BAT_Remcos_MP_MTB{
	meta:
		description = "Trojan:BAT/Remcos.MP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 0a 00 "
		
	strings :
		$a_03_0 = {20 00 10 00 00 8d 90 01 03 01 0d 2b 0a 07 09 16 11 04 6f 90 01 03 0a 08 09 16 09 8e 69 6f 90 01 03 0a 25 13 04 16 30 e5 90 00 } //01 00 
		$a_01_1 = {57 95 02 28 09 0e 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 3c 00 00 00 0b 00 00 00 0f 00 00 00 16 } //01 00 
		$a_01_2 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //01 00  MemoryStream
		$a_01_3 = {57 65 62 52 65 73 70 6f 6e 73 65 } //01 00  WebResponse
		$a_01_4 = {57 65 62 52 65 71 75 65 73 74 } //01 00  WebRequest
		$a_01_5 = {47 65 74 42 79 74 65 73 } //00 00  GetBytes
	condition:
		any of ($a_*)
 
}