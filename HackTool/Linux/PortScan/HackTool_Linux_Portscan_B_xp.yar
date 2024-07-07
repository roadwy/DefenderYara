
rule HackTool_Linux_Portscan_B_xp{
	meta:
		description = "HackTool:Linux/Portscan.B!xp,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {55 48 89 e5 53 48 83 ec 68 89 7d 9c 48 89 75 90 64 48 8b 04 25 28 00 00 00 48 89 45 e8 31 c0 83 7d 9c 05 } //1
		$a_00_1 = {48 8b 45 c0 48 89 45 c8 48 8b 45 c8 0f b6 40 09 3c 11 75 a0 48 8b 45 c8 0f b6 00 83 e0 0f 0f b6 c0 c1 e0 02 66 89 45 ae 0f b7 55 ae 48 8b 45 c0 48 01 d0 48 89 45 d0 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}