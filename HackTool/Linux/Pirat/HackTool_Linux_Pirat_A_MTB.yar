
rule HackTool_Linux_Pirat_A_MTB{
	meta:
		description = "HackTool:Linux/Pirat.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {70 65 69 72 61 74 65 73 2e 69 6e 6a 65 63 74 49 6e 74 6f 41 50 6f 64 56 69 61 41 50 49 53 65 72 76 65 72 } //1 peirates.injectIntoAPodViaAPIServer
		$a_01_1 = {70 65 69 72 61 74 65 73 2e 53 65 72 76 65 72 49 6e 66 6f } //1 peirates.ServerInfo
		$a_01_2 = {65 6e 75 6d 65 72 61 74 65 5f 64 6e 73 2e 67 6f } //1 enumerate_dns.go
		$a_01_3 = {70 65 69 72 61 74 65 73 2e 4b 6f 70 73 41 74 74 61 63 6b 41 57 53 } //1 peirates.KopsAttackAWS
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}