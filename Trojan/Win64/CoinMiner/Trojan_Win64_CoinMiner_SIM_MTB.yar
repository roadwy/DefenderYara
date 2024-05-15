
rule Trojan_Win64_CoinMiner_SIM_MTB{
	meta:
		description = "Trojan:Win64/CoinMiner.SIM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {f7 ef 03 d7 c1 fa 05 8b c2 c1 e8 90 01 01 03 d0 0f be c2 6b c8 3a 40 0f b6 c7 2a c1 04 32 41 30 00 ff c7 4d 8d 40 01 83 ff 27 7c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}