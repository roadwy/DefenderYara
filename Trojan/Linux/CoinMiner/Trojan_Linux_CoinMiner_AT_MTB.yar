
rule Trojan_Linux_CoinMiner_AT_MTB{
	meta:
		description = "Trojan:Linux/CoinMiner.AT!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6c 69 6e 5f 73 74 61 72 74 5f 6d 69 6e 65 72 } //1 lin_start_miner
		$a_01_1 = {6c 69 6e 5f 64 6f 77 6e 6c 6f 61 64 5f 70 61 79 6c 6f 61 64 5f 61 6e 64 5f 65 78 65 63 } //1 lin_download_payload_and_exec
		$a_01_2 = {47 65 74 5f 6d 69 6e 65 72 5f 6e 61 6d 65 } //1 Get_miner_name
		$a_01_3 = {70 6c 61 74 66 6f 72 6d 2e 6c 69 6e 5f 77 61 6c 6b 5f 63 72 6f 6e } //1 platform.lin_walk_cron
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}