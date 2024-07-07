
rule Trojan_Linux_CoinMiner_T_MTB{
	meta:
		description = "Trojan:Linux/CoinMiner.T!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {73 63 6f 70 65 64 5f 6d 65 73 73 61 67 65 5f 77 72 69 74 65 72 2e 68 } //1 scoped_message_writer.h
		$a_00_1 = {43 4f 4d 4d 41 4e 44 5f 52 50 43 5f 47 45 54 4d 49 4e 45 52 44 41 54 41 } //1 COMMAND_RPC_GETMINERDATA
		$a_00_2 = {69 32 70 5f 61 64 64 72 65 73 73 45 45 45 } //1 i2p_addressEEE
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}