
rule Trojan_BAT_AgentTesla_NXO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NXO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {24 31 65 36 30 39 66 32 38 2d 62 61 35 37 2d 34 32 35 63 2d 38 34 38 66 2d 39 61 63 35 37 36 64 31 32 31 33 39 } //01 00  $1e609f28-ba57-425c-848f-9ac576d12139
		$a_01_1 = {51 00 75 00 65 00 73 00 74 00 4b 00 69 00 6e 00 67 00 64 00 6f 00 6d 00 } //01 00  QuestKingdom
		$a_01_2 = {2e 00 57 00 6f 00 72 00 6b 00 65 00 72 00 48 00 65 00 6c 00 70 00 65 00 72 00 } //01 00  .WorkerHelper
		$a_01_3 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_01_4 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //00 00  DebuggerNonUserCodeAttribute
	condition:
		any of ($a_*)
 
}