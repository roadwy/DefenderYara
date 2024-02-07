
rule Trojan_BAT_AgentTesla_DVZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DVZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {79 00 65 00 73 00 2e 00 79 00 65 00 73 00 } //01 00  yes.yes
		$a_01_1 = {46 00 55 00 55 00 4e 00 59 00 41 00 4e 00 44 00 48 00 41 00 52 00 44 00 } //01 00  FUUNYANDHARD
		$a_01_2 = {00 43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 00 } //01 00 
		$a_01_3 = {43 72 79 70 74 6f 53 74 72 65 61 6d 4d 6f 64 65 } //01 00  CryptoStreamMode
		$a_01_4 = {00 54 6f 43 68 61 72 41 72 72 61 79 00 } //01 00 
		$a_01_5 = {00 52 65 76 65 72 73 65 00 } //01 00 
		$a_01_6 = {47 65 74 4d 65 74 68 6f 64 } //01 00  GetMethod
		$a_01_7 = {00 47 65 74 54 79 70 65 00 } //01 00 
		$a_01_8 = {70 00 6f 00 77 00 65 00 72 00 } //00 00  power
	condition:
		any of ($a_*)
 
}