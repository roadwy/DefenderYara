
rule HackTool_Win64_PswDump_AMTB{
	meta:
		description = "HackTool:Win64/PswDump!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_80_0 = {57 65 62 68 6f 6f 6b 20 55 52 4c 20 64 6f 20 44 69 73 63 6f 72 64 20 28 6f 70 63 69 6f 6e 61 6c 20 2d 20 75 73 61 64 6f 20 63 6f 6d 6f 20 66 61 6c 6c 62 61 63 6b 20 73 65 20 41 50 49 } //Webhook URL do Discord (opcional - usado como fallback se API  2
		$a_80_1 = {6f 20 64 6f 20 4d 69 72 61 69 20 53 79 73 74 65 6d } //o do Mirai System  2
		$a_80_2 = {2f 61 70 69 2f 77 65 62 68 6f 6f 6b 2f 74 75 6e 6e 65 6c } ///api/webhook/tunnel  2
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2) >=6
 
}