
rule HackTool_Linux_SAgnt_D_MTB{
	meta:
		description = "HackTool:Linux/SAgnt.D!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {66 65 74 63 68 4f 72 67 49 6e 66 6f } //1 fetchOrgInfo
		$a_01_1 = {68 61 6e 64 6c 65 53 53 48 4c 6f 67 69 6e } //1 handleSSHLogin
		$a_01_2 = {6d 61 69 6e 2e 73 65 6e 64 54 65 6c 65 67 72 61 6d 4d 65 73 73 61 67 65 } //1 main.sendTelegramMessage
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}