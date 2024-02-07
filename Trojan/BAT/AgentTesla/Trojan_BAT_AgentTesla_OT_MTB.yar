
rule Trojan_BAT_AgentTesla_OT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.OT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {53 74 72 65 61 6d 73 68 69 70 5f 53 63 72 65 65 6e 73 68 6f 74 } //01 00  Streamship_Screenshot
		$a_81_1 = {5a 42 4a 55 43 45 35 37 5a 45 37 41 46 34 4a 5a } //01 00  ZBJUCE57ZE7AF4JZ
		$a_81_2 = {41 45 53 5f 44 65 63 72 79 70 74 } //01 00  AES_Decrypt
		$a_81_3 = {46 6c 6f 72 61 } //01 00  Flora
		$a_81_4 = {53 6d 61 72 74 45 78 74 65 6e 73 69 6f 6e 73 } //01 00  SmartExtensions
		$a_81_5 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //00 00  FromBase64String
	condition:
		any of ($a_*)
 
}