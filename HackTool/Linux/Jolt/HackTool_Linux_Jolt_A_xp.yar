
rule HackTool_Linux_Jolt_A_xp{
	meta:
		description = "HackTool:Linux/Jolt.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {6a 6f 6c 74 2e 63 } //01 00  jolt.c
		$a_01_1 = {75 73 61 67 65 3a 20 25 73 20 3c 64 73 74 61 64 64 72 3e 20 3c 73 61 64 64 72 3e 20 5b 6e 75 6d 62 65 72 5d } //01 00  usage: %s <dstaddr> <saddr> [number]
		$a_01_2 = {4a 6f 6c 74 20 76 31 2e 30 } //01 00  Jolt v1.0
		$a_01_3 = {73 70 6f 6f 66 69 6e 67 20 66 72 6f 6d } //00 00  spoofing from
	condition:
		any of ($a_*)
 
}