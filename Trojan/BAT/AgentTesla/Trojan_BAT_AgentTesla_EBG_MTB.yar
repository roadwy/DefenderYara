
rule Trojan_BAT_AgentTesla_EBG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 4c 65 76 65 6c 00 70 6f 00 4f 30 4f 30 4f 00 } //01 00  䰀癥汥瀀oくくO
		$a_01_1 = {00 43 6f 6c 6f 72 54 72 61 6e 73 6c 61 74 6f 72 00 } //01 00 
		$a_01_2 = {00 54 6f 57 69 6e 33 32 00 } //01 00 
		$a_01_3 = {00 47 65 74 54 79 70 65 46 72 6f 6d 48 61 6e 64 6c 65 00 } //01 00 
		$a_01_4 = {00 47 65 74 50 69 78 65 6c 00 } //01 00  䜀瑥楐數l
		$a_01_5 = {00 47 65 74 54 79 70 65 73 } //01 00 
		$a_01_6 = {00 44 69 73 70 6c 61 79 4e 61 6d 65 00 4f 30 4f 30 00 4f 30 4f 30 4f 30 00 } //01 00 
		$a_01_7 = {00 44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}