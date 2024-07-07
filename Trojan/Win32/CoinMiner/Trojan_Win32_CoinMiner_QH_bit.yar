
rule Trojan_Win32_CoinMiner_QH_bit{
	meta:
		description = "Trojan:Win32/CoinMiner.QH!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2d 6f 20 70 6f 6f 6c 2e 73 75 70 70 6f 72 74 78 6d 72 2e 63 6f 6d 3a 35 35 35 35 20 2d 75 } //1 -o pool.supportxmr.com:5555 -u
		$a_01_1 = {00 65 78 70 6c 6f 72 65 72 2e 65 78 65 } //1
		$a_01_2 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //1 Software\Microsoft\Windows\CurrentVersion\Run
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}