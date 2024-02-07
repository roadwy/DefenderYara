
rule Trojan_BAT_AgentTesla_LRL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LRL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 00 } //01 00  夀奙奙奙奙奙奙奙奙奙奙奙奙奙奙奙Y
		$a_01_1 = {00 54 30 30 30 34 00 } //01 00 
		$a_01_2 = {43 6f 6d 70 61 72 65 53 74 72 69 6e 67 } //01 00  CompareString
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 } //01 00  FromBase64
		$a_01_4 = {00 54 30 30 30 31 00 } //01 00 
		$a_01_5 = {00 54 30 30 30 32 00 } //01 00 
		$a_01_6 = {47 65 74 4d 65 74 68 6f 64 } //01 00  GetMethod
		$a_01_7 = {47 65 74 4f 62 6a 65 63 74 56 61 6c 75 65 } //01 00  GetObjectValue
		$a_01_8 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_01_9 = {00 54 30 30 30 35 00 } //00 00 
	condition:
		any of ($a_*)
 
}