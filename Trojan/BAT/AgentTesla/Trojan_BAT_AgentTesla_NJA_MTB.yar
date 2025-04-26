
rule Trojan_BAT_AgentTesla_NJA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NJA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4a 00 67 00 48 00 71 00 51 00 3e 00 41 00 51 00 51 00 66 00 44 00 49 00 67 00 49 00 71 00 51 00 3e 00 41 00 51 00 77 00 65 00 } //1 JgHqQ>AQQfDIgIqQ>AQwe
		$a_01_1 = {24 63 62 35 61 35 36 64 66 2d 62 65 34 39 2d 34 63 35 30 2d 61 31 30 64 2d 61 33 61 31 34 31 61 35 63 66 32 37 } //1 $cb5a56df-be49-4c50-a10d-a3a141a5cf27
		$a_01_2 = {48 42 52 53 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 } //1 HBRS.Resources.resource
		$a_01_3 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}