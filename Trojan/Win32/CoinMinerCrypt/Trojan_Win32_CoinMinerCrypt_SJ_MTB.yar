
rule Trojan_Win32_CoinMinerCrypt_SJ_MTB{
	meta:
		description = "Trojan:Win32/CoinMinerCrypt.SJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {20 e7 64 00 c3 90 01 02 b8 90 01 03 00 81 c6 90 01 04 e8 90 01 01 00 00 00 56 5b bb 90 01 04 31 07 4b 81 ee 90 01 04 47 29 de 39 d7 75 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}