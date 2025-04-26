
rule Trojan_Win32_CoinMiner_RB_bit{
	meta:
		description = "Trojan:Win32/CoinMiner.RB!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 68 75 74 64 6f 77 6e 20 2d 73 20 2d 74 } //1 shutdown -s -t
		$a_01_1 = {6f 70 65 6e 00 00 00 00 65 78 70 6c 6f 72 65 72 2e 65 78 65 } //1
		$a_03_2 = {8a c1 04 25 30 44 0d ?? 41 83 f9 09 72 f2 } //1
		$a_03_3 = {8d 48 25 30 4c 04 ?? 40 83 f8 02 72 f3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}