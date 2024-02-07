
rule Trojan_BAT_AgentTesla_LQJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LQJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {47 65 74 50 69 78 65 6c } //01 00  GetPixel
		$a_01_1 = {46 4c 75 78 43 65 6e 74 65 72 } //01 00  FLuxCenter
		$a_01_2 = {4f 62 6a 65 63 74 49 64 65 6e 74 69 66 69 65 72 } //01 00  ObjectIdentifier
		$a_01_3 = {00 78 73 61 00 } //01 00 
		$a_01_4 = {00 4c 65 76 65 6c 00 } //01 00 
		$a_01_5 = {42 53 54 52 4d 61 72 73 68 61 6c 65 72 } //01 00  BSTRMarshaler
		$a_01_6 = {00 43 6f 6c 6f 72 54 72 61 6e 73 6c 61 74 6f 72 00 } //01 00 
		$a_01_7 = {00 44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 00 } //01 00  䐀扥杵楧杮潍敤s
		$a_01_8 = {00 47 65 74 54 79 70 65 46 72 6f 6d 48 61 6e 64 6c 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}