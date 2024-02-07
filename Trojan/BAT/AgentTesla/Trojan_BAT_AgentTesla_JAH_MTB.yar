
rule Trojan_BAT_AgentTesla_JAH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,36 00 36 00 09 00 00 0a 00 "
		
	strings :
		$a_00_0 = {95 db 95 db 95 db 95 00 70 32 00 58 5f d8 a2 00 6f 77 00 43 5f d8 b5 00 d8 ab d8 ab } //0a 00 
		$a_00_1 = {ab d8 ab d8 ab d8 ab d8 ab 00 d8 a1 d8 a1 d8 a1 d8 a1 d8 a1 d8 a1 d8 a1 d8 a1 d8 a1 } //0a 00 
		$a_00_2 = {a1 d8 a1 d8 a1 d8 a1 d8 a1 d8 a1 00 50 6f 69 6e 74 00 70 31 00 d9 8a d9 8a d9 8a d9 } //0a 00 
		$a_00_3 = {8a d9 8a d9 8a d9 8a d9 8a 00 42 5f d8 a8 00 6b 00 58 58 00 58 58 58 00 d8 b4 d8 b4 } //0a 00 
		$a_00_4 = {b5 d8 b5 d8 b5 d8 b5 d8 b5 d8 b5 d8 b5 d8 b5 d8 b5 d8 b5 d8 b5 d8 b5 00 4c 69 6e 65 } //01 00 
		$a_81_5 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_6 = {46 72 6f 6d 42 61 73 65 36 34 } //01 00  FromBase64
		$a_81_7 = {50 61 72 61 6d 41 72 72 61 79 30 } //01 00  ParamArray0
		$a_81_8 = {41 72 72 61 79 41 74 74 72 69 62 75 74 65 } //00 00  ArrayAttribute
	condition:
		any of ($a_*)
 
}