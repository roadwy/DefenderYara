
rule HackTool_Linux_InviteFlood_B_MTB{
	meta:
		description = "HackTool:Linux/InviteFlood.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {69 6e 76 69 74 65 66 6c 6f 6f 64 } //1 inviteflood
		$a_01_1 = {46 6c 6f 6f 64 20 53 74 61 67 65 } //1 Flood Stage
		$a_01_2 = {68 61 63 6b 5f 6c 69 62 72 61 72 79 2e 63 } //1 hack_library.c
		$a_01_3 = {2d 61 20 66 6c 6f 6f 64 20 74 6f 6f 6c } //1 -a flood tool
		$a_01_4 = {53 49 50 20 50 41 59 4c 4f 41 44 } //1 SIP PAYLOAD
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}