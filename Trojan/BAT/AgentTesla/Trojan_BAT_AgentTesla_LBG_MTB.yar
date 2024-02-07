
rule Trojan_BAT_AgentTesla_LBG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_81_0 = {47 2d 65 2d 74 2d 4d 2d 65 2d 74 2d 68 2d 6f 2d 64 } //01 00  G-e-t-M-e-t-h-o-d
		$a_81_1 = {49 52 6e 52 76 52 6f 52 6b 52 65 } //01 00  IRnRvRoRkRe
		$a_01_2 = {52 65 70 6c 61 63 65 } //01 00  Replace
		$a_01_3 = {54 6f 43 68 61 72 41 72 72 61 79 } //01 00  ToCharArray
		$a_01_4 = {52 65 76 65 72 73 65 } //01 00  Reverse
		$a_01_5 = {49 4f 39 32 31 33 35 37 } //01 00  IO921357
		$a_81_6 = {53 79 73 74 65 6d 2e 43 6f 6e 76 65 72 74 } //01 00  System.Convert
		$a_81_7 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //01 00  InvokeMember
		$a_81_8 = {46 72 6f 6d 42 61 73 65 36 34 } //01 00  FromBase64
		$a_01_9 = {47 65 74 4f 62 6a 65 63 74 56 61 6c 75 65 } //00 00  GetObjectValue
	condition:
		any of ($a_*)
 
}