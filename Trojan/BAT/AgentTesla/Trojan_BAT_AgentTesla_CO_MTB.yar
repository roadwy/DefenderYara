
rule Trojan_BAT_AgentTesla_CO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 04 00 00 06 00 "
		
	strings :
		$a_03_0 = {12 02 28 33 00 00 0a 0a 00 06 17 fe 0e 05 00 20 90 01 04 20 90 01 04 20 90 01 04 61 20 90 01 04 40 10 00 00 00 20 90 01 04 fe 0e 05 00 fe 1c 21 00 00 01 58 00 8d 38 00 00 01 0d 09 16 1f 3a 9d 09 6f 34 00 00 0a 0b 7e 02 00 00 04 07 16 9a 07 17 9a 73 35 00 00 0a 6f 36 00 00 0a 00 00 12 02 28 37 00 00 0a 13 04 11 04 3a 90 00 } //01 00 
		$a_81_1 = {55 47 78 31 5a 32 6c 75 4c 6b 78 68 64 57 35 6a 61 41 3d 3d } //01 00  UGx1Z2luLkxhdW5jaA==
		$a_81_2 = {54 57 46 70 62 67 3d 3d } //01 00  TWFpbg==
		$a_81_3 = {53 79 73 74 65 6d 2e 54 65 78 74 } //00 00  System.Text
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_CO_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.CO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 01 00 "
		
	strings :
		$a_81_0 = {00 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 00 } //01 00  匀卓卓卓卓卓卓卓卓卓卓卓卓卓卓S
		$a_81_1 = {47 65 74 46 69 6c 65 4e 61 6d 65 42 79 55 52 4c } //01 00  GetFileNameByURL
		$a_81_2 = {47 65 74 4f 62 6a 65 63 74 56 61 6c 75 65 } //01 00  GetObjectValue
		$a_81_3 = {53 74 72 52 65 76 65 72 73 65 } //01 00  StrReverse
		$a_81_4 = {46 72 6f 6d 42 61 73 65 36 34 43 68 61 72 41 72 72 61 79 } //01 00  FromBase64CharArray
		$a_81_5 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //01 00  InvokeMember
		$a_81_6 = {47 5a 69 70 53 74 72 65 61 6d } //01 00  GZipStream
		$a_81_7 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_8 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_81_9 = {69 6d 69 6d 69 6d 69 6d 69 6d } //01 00  imimimimim
		$a_81_10 = {00 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 00 } //00 00  砀硸硸硸硸硸硸硸硸x
	condition:
		any of ($a_*)
 
}