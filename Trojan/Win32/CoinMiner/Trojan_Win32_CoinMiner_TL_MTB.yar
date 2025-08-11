
rule Trojan_Win32_CoinMiner_TL_MTB{
	meta:
		description = "Trojan:Win32/CoinMiner.TL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 8d cc f8 ff ff 51 6a 01 68 cd 0d 6e 52 8b 95 c4 fd ff ff 52 e8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}