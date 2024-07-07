
rule Trojan_Win32_CoinMiner_BF_bit{
	meta:
		description = "Trojan:Win32/CoinMiner.BF!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {eb 0d 0f be 45 90 01 01 0f be 4d 90 01 01 33 c1 88 45 90 01 01 8b 45 90 01 01 03 45 90 01 01 8a 4d 90 01 01 88 08 e9 90 01 03 ff 90 00 } //2
		$a_03_1 = {6a 00 6a 00 ff 15 90 01 03 10 50 68 90 01 03 10 6a 0d ff 15 90 01 03 10 a3 90 01 03 10 83 3d 90 01 03 10 00 75 08 83 c8 ff e9 90 01 03 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}