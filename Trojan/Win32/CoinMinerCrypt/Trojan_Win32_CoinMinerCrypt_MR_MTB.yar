
rule Trojan_Win32_CoinMinerCrypt_MR_MTB{
	meta:
		description = "Trojan:Win32/CoinMinerCrypt.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {29 c2 43 89 90 01 01 ba 90 01 04 39 90 01 01 90 18 bf 90 01 04 42 e8 90 01 04 09 90 01 01 42 4a 31 90 01 01 89 90 01 01 81 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}