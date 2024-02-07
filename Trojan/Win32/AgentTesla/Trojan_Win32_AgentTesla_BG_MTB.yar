
rule Trojan_Win32_AgentTesla_BG_MTB{
	meta:
		description = "Trojan:Win32/AgentTesla.BG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {43 3a 5c 78 61 6d 70 70 5c 68 74 64 6f 63 73 5c 43 72 79 70 74 6f 72 5c 90 1f 50 00 5c 4c 6f 61 64 65 72 5c 52 65 6c 65 61 73 65 5c 4c 6f 61 64 65 72 2e 70 64 62 90 00 } //01 00 
		$a_00_1 = {4c 4c 44 20 50 44 42 } //00 00  LLD PDB
	condition:
		any of ($a_*)
 
}