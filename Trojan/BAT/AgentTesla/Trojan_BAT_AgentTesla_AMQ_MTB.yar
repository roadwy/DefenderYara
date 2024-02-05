
rule Trojan_BAT_AgentTesla_AMQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AMQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 08 00 00 0a 00 "
		
	strings :
		$a_03_0 = {11 05 09 11 90 01 01 18 5a 18 90 01 05 1f 10 28 90 01 04 d2 90 00 } //02 00 
		$a_80_1 = {47 65 74 54 79 70 65 } //GetType  02 00 
		$a_80_2 = {49 6e 76 6f 6b 65 } //Invoke  02 00 
		$a_80_3 = {47 65 74 4d 65 74 68 6f 64 } //GetMethod  02 00 
		$a_80_4 = {4d 65 74 72 6f 46 72 61 6d 65 77 6f 72 6b 2e 4d 65 74 72 6f 5f 42 75 74 74 6f 6e } //MetroFramework.Metro_Button  02 00 
		$a_80_5 = {52 65 76 65 72 73 65 } //Reverse  02 00 
		$a_80_6 = {52 65 70 6c 61 63 65 } //Replace  02 00 
		$a_80_7 = {54 6f 43 68 61 72 41 72 72 61 79 } //ToCharArray  00 00 
	condition:
		any of ($a_*)
 
}