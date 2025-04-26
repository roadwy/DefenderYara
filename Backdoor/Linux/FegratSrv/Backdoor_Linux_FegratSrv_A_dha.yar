
rule Backdoor_Linux_FegratSrv_A_dha{
	meta:
		description = "Backdoor:Linux/FegratSrv.A!dha,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {52 65 64 46 6c 61 72 65 2f 67 6f 72 61 74 5f 73 65 72 76 65 72 2e 43 6f 6e 66 69 67 } //1 RedFlare/gorat_server.Config
		$a_00_1 = {52 65 64 46 6c 61 72 65 2f 67 6f 72 61 74 5f 73 65 72 76 65 72 2e 28 2a 53 65 72 76 65 72 29 2e 67 65 74 47 6f 52 61 74 42 69 6e 61 72 79 } //1 RedFlare/gorat_server.(*Server).getGoRatBinary
		$a_00_2 = {52 65 64 46 6c 61 72 65 2f 67 6f 72 61 74 5f 73 65 72 76 65 72 2e 48 54 54 50 50 72 6f 78 79 53 65 72 76 65 72 } //1 RedFlare/gorat_server.HTTPProxyServer
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}