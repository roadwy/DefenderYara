
rule Trojan_BAT_KillMBR_ARAU_MTB{
	meta:
		description = "Trojan:BAT/KillMBR.ARAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {5c 57 69 6e 44 65 61 74 68 5c 57 69 6e 44 65 61 74 68 5c 6f 62 6a 5c 44 65 62 75 67 5c 57 69 6e 44 65 61 74 68 2e 70 64 62 } //06 00 
		$a_80_1 = {57 69 6e 64 6f 77 73 20 69 73 20 6e 6f 77 20 44 45 41 44 } //Windows is now DEAD  03 00 
		$a_80_2 = {52 65 41 67 65 6e 74 63 2e 65 78 65 } //ReAgentc.exe  03 00 
		$a_80_3 = {2f 64 69 73 61 62 6c 65 } ///disable  02 00 
		$a_80_4 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 } //\\.\PhysicalDrive0  00 00 
	condition:
		any of ($a_*)
 
}