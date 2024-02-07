
rule Trojan_BAT_ElysiumStealer_EK_MTB{
	meta:
		description = "Trojan:BAT/ElysiumStealer.EK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,43 00 43 00 0c 00 00 32 00 "
		
	strings :
		$a_81_0 = {61 64 73 61 73 64 61 73 61 } //32 00  adsasdasa
		$a_81_1 = {62 66 64 66 62 64 66 62 64 66 62 64 66 62 64 66 62 64 66 } //32 00  bfdfbdfbdfbdfbdfbdf
		$a_81_2 = {64 73 66 66 64 73 66 73 64 66 73 } //0a 00  dsffdsfsdfs
		$a_81_3 = {70 70 70 68 68 79 66 } //0a 00  ppphhyf
		$a_81_4 = {67 66 67 66 64 66 64 67 } //01 00  gfgfdfdg
		$a_81_5 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  ToBase64String
		$a_81_6 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //01 00  get_CurrentDomain
		$a_81_7 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_81_8 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //01 00  DebuggingModes
		$a_81_9 = {47 65 74 54 79 70 65 73 } //01 00  GetTypes
		$a_81_10 = {43 6f 6e 76 65 72 74 } //01 00  Convert
		$a_81_11 = {49 6e 76 6f 6b 65 } //00 00  Invoke
	condition:
		any of ($a_*)
 
}