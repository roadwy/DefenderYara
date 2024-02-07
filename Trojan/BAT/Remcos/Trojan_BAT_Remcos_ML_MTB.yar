
rule Trojan_BAT_Remcos_ML_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 07 00 00 0a 00 "
		
	strings :
		$a_01_0 = {57 95 02 20 09 0a 00 00 00 00 00 00 00 00 00 00 01 00 00 00 39 00 00 00 08 00 00 00 87 00 00 00 1b } //01 00 
		$a_01_1 = {24 30 34 62 36 35 63 62 38 2d 66 32 34 62 2d 34 64 65 39 2d 38 66 39 31 2d 64 35 37 63 30 65 32 36 33 33 61 33 } //01 00  $04b65cb8-f24b-4de9-8f91-d57c0e2633a3
		$a_01_2 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //01 00  MemoryStream
		$a_01_3 = {57 65 62 52 65 71 75 65 73 74 } //01 00  WebRequest
		$a_01_4 = {57 65 62 52 65 73 70 6f 6e 73 65 } //01 00  WebResponse
		$a_01_5 = {47 65 74 44 6f 6d 61 69 6e } //01 00  GetDomain
		$a_01_6 = {47 65 74 54 79 70 65 } //00 00  GetType
	condition:
		any of ($a_*)
 
}