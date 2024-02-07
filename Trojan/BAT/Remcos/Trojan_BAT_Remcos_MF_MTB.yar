
rule Trojan_BAT_Remcos_MF_MTB{
	meta:
		description = "Trojan:BAT/Remcos.MF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 07 00 00 0a 00 "
		
	strings :
		$a_01_0 = {57 1d a2 09 09 1f 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 8c 00 00 00 11 00 00 00 48 00 00 00 a9 00 00 00 58 } //01 00 
		$a_01_1 = {24 61 65 30 37 66 31 39 66 2d 61 30 37 39 2d 34 37 37 65 2d 62 38 36 62 2d 65 36 63 38 36 66 33 66 38 33 64 33 } //01 00  $ae07f19f-a079-477e-b86b-e6c86f3f83d3
		$a_01_2 = {67 65 74 5f 41 73 73 65 6d 62 6c 79 } //01 00  get_Assembly
		$a_01_3 = {53 74 72 52 65 76 65 72 73 65 } //01 00  StrReverse
		$a_01_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_5 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_01_6 = {43 72 65 61 74 65 5f 5f 49 6e 73 74 61 6e 63 65 5f 5f } //00 00  Create__Instance__
	condition:
		any of ($a_*)
 
}