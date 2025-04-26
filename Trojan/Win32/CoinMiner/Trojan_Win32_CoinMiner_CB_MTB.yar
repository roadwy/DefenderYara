
rule Trojan_Win32_CoinMiner_CB_MTB{
	meta:
		description = "Trojan:Win32/CoinMiner.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 03 01 cf 81 ef [0-04] 81 c3 04 00 00 00 be [0-04] 81 e9 [0-04] 39 d3 75 dc } //2
		$a_01_1 = {89 db 31 10 4b 41 01 db 40 01 cb 39 f8 75 d9 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=2
 
}