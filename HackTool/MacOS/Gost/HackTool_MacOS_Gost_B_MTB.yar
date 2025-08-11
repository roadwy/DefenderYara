
rule HackTool_MacOS_Gost_B_MTB{
	meta:
		description = "HackTool:MacOS/Gost.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {67 6f 2d 67 6f 73 74 2f 63 6f 72 65 2f 6c 6f 67 67 65 72 2e 4c 6f 67 67 65 72 5d 29 2e 49 73 52 65 67 69 73 74 65 72 65 64 } //1 go-gost/core/logger.Logger]).IsRegistered
		$a_01_1 = {6d 61 69 6e 2e 62 75 69 6c 64 41 50 49 53 65 72 76 69 63 65 2e 41 63 63 65 73 73 4c 6f 67 4f 70 74 69 6f 6e 2e 66 75 6e 63 32 } //1 main.buildAPIService.AccessLogOption.func2
		$a_01_2 = {67 6f 73 74 2f 78 2f 68 61 6e 64 6c 65 72 2f 74 75 6e 6e 65 6c 2e 70 61 72 73 65 54 75 6e 6e 65 6c 49 44 } //1 gost/x/handler/tunnel.parseTunnelID
		$a_01_3 = {67 6f 2d 67 6f 73 74 2f 72 65 6c 61 79 2e 4e 65 77 50 72 69 76 61 74 65 54 75 6e 6e 65 6c 49 44 } //1 go-gost/relay.NewPrivateTunnelID
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}