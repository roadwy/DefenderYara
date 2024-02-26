
rule TrojanDropper_BAT_AgentTesla_ARA_MTB{
	meta:
		description = "TrojanDropper:BAT/AgentTesla.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 02 00 "
		
	strings :
		$a_80_0 = {59 6f 75 72 40 53 70 6c 69 74 40 48 65 72 65 } //Your@Split@Here  02 00 
		$a_80_1 = {59 4f 55 52 40 50 41 53 53 57 4f 52 44 40 48 45 52 45 } //YOUR@PASSWORD@HERE  02 00 
		$a_80_2 = {5c 66 69 6c 65 31 2e 65 78 65 } //\file1.exe  02 00 
		$a_80_3 = {57 69 6e 64 6f 77 73 41 70 70 33 2e 52 65 73 6f 75 72 63 65 73 } //WindowsApp3.Resources  00 00 
	condition:
		any of ($a_*)
 
}