
rule Trojan_BAT_CoinMiner_MBP_MTB{
	meta:
		description = "Trojan:BAT/CoinMiner.MBP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {43 00 3a 00 5c 00 46 00 79 00 5c 00 66 00 79 00 5f 00 67 00 75 00 61 00 72 00 64 00 2e 00 64 00 61 00 74 00 61 00 } //1 C:\Fy\fy_guard.data
		$a_01_1 = {87 65 f6 4e 22 4e 31 59 0c ff f7 8b 73 51 40 67 d2 6b 0e 54 cd 91 b0 65 2f 54 a8 52 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}