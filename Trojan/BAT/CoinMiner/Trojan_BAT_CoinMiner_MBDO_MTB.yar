
rule Trojan_BAT_CoinMiner_MBDO_MTB{
	meta:
		description = "Trojan:BAT/CoinMiner.MBDO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {34 44 35 41 39 29 29 33 29 29 29 30 34 29 29 29 5b 5b 5b 5b 5b 5b 5b 5b 29 29 42 38 29 29 29 29 29 29 29 34 } //1 4D5A9))3)))04)))[[[[[[[[))B8)))))))4
		$a_01_1 = {29 30 38 29 29 29 29 45 31 5b 5b 42 41 30 45 29 42 34 30 39 43 44 32 31 42 38 30 31 34 43 43 44 32 31 35 34 36 38 36 39 37 33 32 30 37 30 37 32 36 5b 5b 36 37 37 32 36 31 36 44 } //1 )08))))E1[[BA0E)B409CD21B8014CCD21546869732070726[[6772616D
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}