
rule Trojan_Win64_CoinMiner_MTC_bit{
	meta:
		description = "Trojan:Win64/CoinMiner.MTC!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 63 c8 48 8d 90 02 10 54 24 30 48 03 90 01 01 8d 48 40 ff 90 01 01 30 0a 83 90 02 10 72 90 00 } //1
		$a_03_1 = {33 c0 c7 44 90 01 02 6e 70 7a 73 33 ed c7 44 90 01 02 71 75 74 6a 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}