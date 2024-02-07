
rule Trojan_Win32_AgentTesla_EVX_MTB{
	meta:
		description = "Trojan:Win32/AgentTesla.EVX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 00 ff 15 90 01 04 6a 00 ff 15 90 01 04 6a 00 ff 15 90 01 04 6a 00 ff 15 90 01 04 6a 00 ff 15 90 01 04 6a 00 ff 15 90 01 04 6a 00 ff 15 90 01 04 68 90 01 04 68 90 01 04 ff 15 90 00 } //01 00 
		$a_01_1 = {45 78 63 65 70 2e 74 63 74 } //01 00  Excep.tct
		$a_01_2 = {74 69 6f 6e 43 61 74 63 68 65 72 } //01 00  tionCatcher
		$a_01_3 = {4d 59 39 34 37 } //01 00  MY947
		$a_01_4 = {39 34 37 5c 52 65 6c 65 61 73 65 5c 39 34 37 2e 70 64 62 } //00 00  947\Release\947.pdb
	condition:
		any of ($a_*)
 
}