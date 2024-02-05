
rule Trojan_Win32_CoinMinerCrypt_SI_MTB{
	meta:
		description = "Trojan:Win32/CoinMinerCrypt.SI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {29 fa 81 ea 90 01 04 e8 90 01 01 00 00 00 29 d7 89 ff 31 1e 89 d7 4a 81 c2 90 01 04 46 21 d7 52 8b 3c 24 83 c4 04 39 ce 75 90 01 01 81 ea 90 01 04 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}