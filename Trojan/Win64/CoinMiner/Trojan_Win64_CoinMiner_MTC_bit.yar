
rule Trojan_Win64_CoinMiner_MTC_bit{
	meta:
		description = "Trojan:Win64/CoinMiner.MTC!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 63 c8 48 8d [0-10] 54 24 30 48 03 ?? 8d 48 40 ff ?? 30 0a 83 [0-10] 72 } //1
		$a_03_1 = {33 c0 c7 44 ?? ?? 6e 70 7a 73 33 ed c7 44 ?? ?? 71 75 74 6a } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}