
rule Trojan_Win32_CoinMiner_BZ_bit{
	meta:
		description = "Trojan:Win32/CoinMiner.BZ!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {44 3a 5c 70 72 69 76 5c 77 6f 72 6b 5c 6c 6f 6c 6f 6c 6f 5c 6d 61 6c 77 6d 6d 6d 90 02 20 2e 70 64 62 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}