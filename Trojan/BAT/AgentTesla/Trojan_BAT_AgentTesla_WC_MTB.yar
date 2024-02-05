
rule Trojan_BAT_AgentTesla_WC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.WC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 08 00 00 03 00 "
		
	strings :
		$a_80_0 = {61 70 70 6c 69 63 61 74 69 6f 6e 2f 6a 73 6f 6e 3b 20 63 68 61 72 73 65 74 3d 75 74 66 2d 38 } //application/json; charset=utf-8  03 00 
		$a_80_1 = {53 74 72 65 61 6d 52 65 61 64 65 72 } //StreamReader  03 00 
		$a_80_2 = {76 32 2f 70 72 6f 63 65 73 73 2e 70 68 70 } //v2/process.php  03 00 
		$a_80_3 = {68 74 74 70 57 65 62 52 65 71 75 65 73 74 } //httpWebRequest  03 00 
		$a_80_4 = {63 6f 73 74 75 72 61 2e 6e 65 77 74 6f 6e 73 6f 66 74 2e 6a 73 6f 6e 2e 64 6c 6c 2e 63 6f 6d 70 72 65 73 73 65 64 } //costura.newtonsoft.json.dll.compressed  03 00 
		$a_80_5 = {63 6f 73 74 75 72 61 2e 63 6f 73 74 75 72 61 2e 64 6c 6c 2e 63 6f 6d 70 72 65 73 73 65 64 } //costura.costura.dll.compressed  03 00 
		$a_80_6 = {5a 6f 6f 20 68 61 73 20 7b 30 7d 20 61 6e 69 6d 61 6c 73 2e } //Zoo has {0} animals.  03 00 
		$a_80_7 = {75 6e 77 69 72 65 64 6c 61 62 73 } //unwiredlabs  00 00 
	condition:
		any of ($a_*)
 
}