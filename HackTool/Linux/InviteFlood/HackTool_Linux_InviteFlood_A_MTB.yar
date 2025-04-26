
rule HackTool_Linux_InviteFlood_A_MTB{
	meta:
		description = "HackTool:Linux/InviteFlood.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 f0 c6 00 00 8b 45 ec 89 04 24 e8 fa ed ff ff 89 45 e0 81 7d e0 ff 00 00 00 7f ?? 8b 45 ec 0f b6 00 0f be c0 83 e8 30 83 f8 09 } //1
		$a_01_1 = {83 ec 28 8b 45 0c 89 c2 c1 fa 1f c1 ea 1c 01 d0 c1 f8 04 89 45 ec 8b 45 0c 89 c2 c1 fa 1f c1 ea 1c 01 d0 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}