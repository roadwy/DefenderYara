
rule Trojan_BAT_AgentTesla_EK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {13 07 11 05 11 07 1b 8d 01 00 00 01 13 0a 11 0a 16 72 90 01 03 70 28 07 00 00 06 a2 11 0a 17 1f 40 8c 07 00 00 01 a2 11 0a 18 11 07 17 90 00 } //01 00 
		$a_03_1 = {11 07 6f 1c 00 00 0a 18 59 6f 1b 00 00 0a 28 06 00 00 06 a2 11 0a 19 1f 40 8c 07 00 00 01 a2 11 0a 1a 72 90 01 03 70 28 07 00 00 06 a2 11 0a 28 1d 00 00 0a 6f 1e 00 00 0a 13 05 11 05 1f 22 28 01 00 00 2b 3a 64 ff ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_EK_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.EK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 0a 00 "
		
	strings :
		$a_03_0 = {70 03 11 04 18 6f 90 01 03 0a 28 90 01 03 0a 28 90 01 03 0a 04 07 6f 90 01 03 0a 28 90 01 03 0a 6a 61 b7 28 90 01 03 0a 13 07 12 07 28 90 01 03 0a 13 05 08 11 05 6f 90 01 03 0a 26 07 04 6f 90 01 03 0a 17 da 33 03 90 00 } //0a 00 
		$a_03_1 = {70 03 11 04 18 6f 90 01 03 0a 28 90 01 03 0a 28 90 01 03 0a 04 07 6f 90 01 03 0a 28 90 01 03 0a 6a 61 b7 28 90 01 03 0a 28 90 01 03 0a 13 05 08 11 05 6f 90 01 03 0a 26 07 04 6f 90 01 03 0a 17 da 33 03 90 00 } //01 00 
		$a_81_2 = {58 4f 52 5f 44 65 63 72 79 70 74 } //01 00  XOR_Decrypt
		$a_81_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //00 00  CreateInstance
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_EK_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.EK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 01 00 "
		
	strings :
		$a_81_0 = {00 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 00 } //01 00  匀卓卓卓卓卓卓卓卓卓卓卓卓卓卓S
		$a_81_1 = {41 5a 58 43 43 43 43 43 43 43 43 43 43 43 43 43 43 43 43 43 43 43 } //01 00  AZXCCCCCCCCCCCCCCCCCCC
		$a_81_2 = {54 6f 43 68 61 72 41 72 72 61 79 } //01 00  ToCharArray
		$a_81_3 = {53 74 72 52 65 76 65 72 73 65 } //01 00  StrReverse
		$a_81_4 = {46 72 6f 6d 42 61 73 65 36 34 43 68 61 72 41 72 72 61 79 } //01 00  FromBase64CharArray
		$a_81_5 = {41 63 74 69 76 61 74 6f 72 } //01 00  Activator
		$a_81_6 = {47 5a 69 70 53 74 72 65 61 6d } //01 00  GZipStream
		$a_81_7 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_8 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_81_9 = {69 6d 69 6d 69 6d 69 6d 69 6d } //01 00  imimimimim
		$a_81_10 = {00 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 00 } //00 00  砀硸硸硸硸硸硸硸硸x
	condition:
		any of ($a_*)
 
}