
rule Trojan_MacOS_MythicPoseidon_A_MTB{
	meta:
		description = "Trojan:MacOS/MythicPoseidon.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {2f 75 70 64 61 74 65 5f 63 32 2e 67 6f } //1 /update_c2.go
		$a_01_1 = {67 69 74 68 75 62 2e 63 6f 6d 2f 4d 79 74 68 69 63 41 67 65 6e 74 73 2f } //1 github.com/MythicAgents/
		$a_01_2 = {2f 75 74 69 6c 73 2f 70 32 70 2f 70 6f 73 65 69 64 6f 6e 5f 74 63 70 2e 67 6f } //1 /utils/p2p/poseidon_tcp.go
		$a_01_3 = {53 65 6e 64 46 69 6c 65 54 6f 4d 79 74 68 69 63 } //1 SendFileToMythic
		$a_01_4 = {2a 70 32 70 2e 77 65 62 73 68 65 6c 6c 52 65 73 70 6f 6e 73 65 } //1 *p2p.webshellResponse
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}