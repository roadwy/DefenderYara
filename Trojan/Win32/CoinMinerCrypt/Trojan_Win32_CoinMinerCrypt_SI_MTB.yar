
rule Trojan_Win32_CoinMinerCrypt_SI_MTB{
	meta:
		description = "Trojan:Win32/CoinMinerCrypt.SI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {29 fa 81 ea ?? ?? ?? ?? e8 ?? 00 00 00 29 d7 89 ff 31 1e 89 d7 4a 81 c2 ?? ?? ?? ?? 46 21 d7 52 8b 3c 24 83 c4 04 39 ce 75 ?? 81 ea ?? ?? ?? ?? c3 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}