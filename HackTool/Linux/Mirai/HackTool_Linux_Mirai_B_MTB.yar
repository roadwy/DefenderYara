
rule HackTool_Linux_Mirai_B_MTB{
	meta:
		description = "HackTool:Linux/Mirai.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 42 75 69 6c 64 4b 69 6c 6c 53 65 6c 66 } //1 main.BuildKillSelf
		$a_01_1 = {2f 6d 69 72 61 69 2f 63 6e 63 2f 62 6f 74 2e 67 6f } //1 /mirai/cnc/bot.go
		$a_01_2 = {6d 61 69 6e 2e 41 74 74 61 63 6b 53 65 6e 64 } //1 main.AttackSend
		$a_01_3 = {6d 61 69 6e 2e 65 6e 63 72 79 70 74 43 72 65 64 65 6e 74 69 61 6c 73 } //1 main.encryptCredentials
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}