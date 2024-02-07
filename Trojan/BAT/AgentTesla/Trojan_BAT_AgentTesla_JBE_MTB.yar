
rule Trojan_BAT_AgentTesla_JBE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0e 00 00 01 00 "
		
	strings :
		$a_81_0 = {5f 32 36 5f 4b 69 73 73 79 } //01 00  _26_Kissy
		$a_81_1 = {61 6e 67 75 69 6c 6c 61 5f 31 36 78 31 36 5f 33 32 39 32 34 } //01 00  anguilla_16x16_32924
		$a_81_2 = {5f 32 35 5f 4e 6f 74 5f 67 75 69 6c 74 79 } //01 00  _25_Not_guilty
		$a_81_3 = {61 6c 61 6e 64 5f 31 36 78 31 36 5f 33 32 39 30 38 } //01 00  aland_16x16_32908
		$a_81_4 = {61 6c 62 61 6e 69 61 5f 31 36 78 31 36 5f 33 32 39 30 39 } //01 00  albania_16x16_32909
		$a_81_5 = {5f 32 34 5f 48 61 79 } //01 00  _24_Hay
		$a_81_6 = {61 6c 67 65 72 69 61 5f 31 36 78 31 36 5f 33 32 39 37 32 } //01 00  algeria_16x16_32972
		$a_81_7 = {5f 32 37 5f 47 6f 61 74 73 65 } //01 00  _27_Goatse
		$a_81_8 = {5f 32 38 5f 4e 6f 6d 6e 6f 6d 6e 6f 6d } //01 00  _28_Nomnomnom
		$a_81_9 = {46 72 23 6f 6d 42 61 23 73 65 36 34 53 74 72 23 69 6e 67 } //01 00  Fr#omBa#se64Str#ing
		$a_81_10 = {47 65 74 4d 65 74 68 6f 64 } //01 00  GetMethod
		$a_81_11 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //01 00  GetExecutingAssembly
		$a_81_12 = {52 65 70 6c 61 63 65 } //01 00  Replace
		$a_81_13 = {43 6c 61 73 73 4c 69 62 72 61 72 79 } //00 00  ClassLibrary
	condition:
		any of ($a_*)
 
}