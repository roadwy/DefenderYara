
rule PUA_Linux_CoinMiner_crng{
	meta:
		description = "PUA:Linux/CoinMiner!crng,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {63 72 79 70 74 6f 6e 69 67 68 74 20 2d 6f 20 73 74 72 61 74 75 6d 2b 74 63 70 3a 2f 2f 70 6f 6f 6c 2e } //1 cryptonight -o stratum+tcp://pool.
	condition:
		((#a_00_0  & 1)*1) >=1
 
}