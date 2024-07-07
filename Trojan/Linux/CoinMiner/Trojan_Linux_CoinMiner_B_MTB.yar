
rule Trojan_Linux_CoinMiner_B_MTB{
	meta:
		description = "Trojan:Linux/CoinMiner.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {31 c0 f3 aa 48 8b 7d 00 e8 38 10 00 00 31 ff e8 fa 1c 00 00 48 89 c3 e8 63 1d 00 00 8d 3c 18 e8 52 09 00 00 e8 ae 04 00 00 be 41 00 00 00 31 c0 } //1
		$a_00_1 = {2f 74 6d 70 2f 2e 73 79 73 74 65 6d 64 2e 31 } //1 /tmp/.systemd.1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}