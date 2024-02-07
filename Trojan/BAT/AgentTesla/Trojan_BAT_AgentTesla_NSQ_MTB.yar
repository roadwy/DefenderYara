
rule Trojan_BAT_AgentTesla_NSQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NSQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {24 31 35 30 62 65 37 35 61 2d 34 65 35 36 2d 34 64 30 32 2d 62 38 33 36 2d 66 35 33 39 33 38 64 30 34 62 64 36 } //01 00  $150be75a-4e56-4d02-b836-f53938d04bd6
		$a_01_1 = {54 69 6d 65 62 6f 78 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //01 00  Timebox.Properties.Resources.resources
		$a_01_2 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerNonUserCodeAttribute
		$a_01_3 = {47 65 74 4d 65 74 68 6f 64 } //01 00  GetMethod
		$a_01_4 = {52 65 70 6c 61 63 65 } //00 00  Replace
	condition:
		any of ($a_*)
 
}