
rule Trojan_BAT_AgentTesla_WF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.WF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 04 00 00 0a 00 "
		
	strings :
		$a_00_0 = {fe 0e 00 00 38 00 00 00 00 fe 0c 00 00 45 02 00 00 00 57 00 00 00 20 00 00 00 38 52 00 00 00 28 1e 00 00 0a 14 fe 06 16 00 00 06 73 1f 00 00 0a 6f 20 00 00 0a 38 1b 00 00 00 17 3a 48 00 00 00 20 00 00 00 00 7e 76 00 00 04 3a be ff ff ff 26 38 b4 ff ff ff } //03 00 
		$a_80_1 = {4d 75 6c 74 69 63 61 73 74 44 65 6c 65 67 61 74 65 } //MulticastDelegate  03 00 
		$a_80_2 = {50 72 6f 63 63 65 73 6f 72 44 65 63 6f 72 61 74 6f 72 52 65 73 6f 6c 76 65 72 } //ProccesorDecoratorResolver  03 00 
		$a_80_3 = {50 72 6f 78 79 41 74 74 72 69 62 75 74 65 50 6f 6f 6c } //ProxyAttributePool  00 00 
	condition:
		any of ($a_*)
 
}