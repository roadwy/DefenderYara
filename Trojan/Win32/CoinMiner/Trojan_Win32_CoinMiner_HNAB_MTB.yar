
rule Trojan_Win32_CoinMiner_HNAB_MTB{
	meta:
		description = "Trojan:Win32/CoinMiner.HNAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_01_0 = {59 3e c3 6f d2 45 c3 6f 31 47 c3 6f 80 46 c3 6f 00 00 00 00 b9 8e c6 7d a9 f5 c8 7d 00 00 00 00 22 12 d7 7d 56 18 d7 7d 47 43 d7 7d 28 4d d7 7d } //2
		$a_01_1 = {3a f7 0e 66 b7 77 10 66 c1 fd 0e 66 ec 9c 0d 66 ee f6 0e 66 bf b6 0d 66 0c 94 10 66 44 77 10 66 } //2
		$a_01_2 = {09 fb 0e 66 3a f8 0e 66 c9 76 10 66 53 75 10 66 1b bb 0d 66 fa 0d 0e 66 } //2
		$a_03_3 = {00 ff 25 1c 11 40 00 90 09 05 00 2e 65 78 65 } //1
		$a_01_4 = {2e 74 65 78 74 00 00 00 64 08 02 00 00 10 00 00 00 10 02 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 20 00 00 60 2e 64 61 74 61 00 00 00 b0 0a 00 00 00 20 02 00 00 10 00 00 00 20 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1) >=7
 
}