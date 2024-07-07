
rule Trojan_Win32_CoinStealer_GNM_MTB{
	meta:
		description = "Trojan:Win32/CoinStealer.GNM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {89 45 f4 8b 45 14 81 e8 90 01 04 03 45 90 01 01 83 f0 90 01 01 2b 45 90 01 01 33 c0 81 e8 90 01 04 33 05 90 01 04 81 e8 90 01 04 89 45 90 01 01 8b c7 5f 58 8b e5 5d c3 90 00 } //10
		$a_02_1 = {89 45 20 b9 2c 00 00 00 81 e9 90 01 04 03 0d 90 01 04 81 e9 90 01 04 33 0d 90 01 04 2b 4d 1c 89 4d cc 8b c5 59 8b e5 5d c3 90 00 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}