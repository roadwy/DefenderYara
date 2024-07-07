
rule Trojan_Linux_Coinminer_B{
	meta:
		description = "Trojan:Linux/Coinminer.B,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {2e 6f 6e 69 6f 6e } //1 .onion
		$a_00_1 = {2e 69 32 70 } //1 .i2p
		$a_00_2 = {73 74 61 72 74 5f 6d 69 6e 69 6e 67 } //1 start_mining
		$a_00_3 = {73 74 6f 70 5f 6d 69 6e 69 6e 67 } //1 stop_mining
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}