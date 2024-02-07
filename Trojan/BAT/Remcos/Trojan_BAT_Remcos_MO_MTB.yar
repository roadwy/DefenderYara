
rule Trojan_BAT_Remcos_MO_MTB{
	meta:
		description = "Trojan:BAT/Remcos.MO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {57 9f a2 29 09 1f 00 00 00 00 00 00 00 00 00 00 01 00 00 00 d6 00 00 00 50 00 00 00 35 01 } //01 00 
		$a_01_1 = {24 35 33 35 64 31 63 65 66 2d 61 62 31 36 2d 34 36 36 39 2d 61 66 38 37 2d 34 35 34 34 33 64 61 33 66 62 33 39 } //01 00  $535d1cef-ab16-4669-af87-45443da3fb39
		$a_01_2 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //01 00  MemoryStream
		$a_01_3 = {41 70 70 44 6f 6d 61 69 6e } //01 00  AppDomain
		$a_01_4 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //01 00  DebuggingModes
		$a_01_5 = {47 65 74 42 79 74 65 73 } //00 00  GetBytes
	condition:
		any of ($a_*)
 
}