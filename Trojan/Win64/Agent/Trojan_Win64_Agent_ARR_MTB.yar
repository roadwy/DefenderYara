
rule Trojan_Win64_Agent_ARR_MTB{
	meta:
		description = "Trojan:Win64/Agent.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 45 49 76 4b 41 6b 48 2e 66 75 6e 63 31 2e 31 } //15 main.EIvKAkH.func1.1
		$a_01_1 = {6d 61 69 6e 2e 54 58 70 45 46 66 42 72 2e 66 75 6e 63 31 2e 67 6f 77 72 61 70 31 } //10 main.TXpEFfBr.func1.gowrap1
		$a_03_2 = {48 89 44 24 30 48 8b 59 ?? 48 8b 11 48 c1 e0 ?? 48 8b 0c 02 } //5
	condition:
		((#a_01_0  & 1)*15+(#a_01_1  & 1)*10+(#a_03_2  & 1)*5) >=30
 
}
rule Trojan_Win64_Agent_ARR_MTB_2{
	meta:
		description = "Trojan:Win64/Agent.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {49 8d 43 01 43 30 4c 10 ff 4c 8b df c1 ea ?? 8d 0c 92 03 c9 } //12
		$a_81_1 = {7a 66 7c 31 3a 6c 63 7c 31 3a 64 64 7c 31 3a 33 74 7c 30 38 3a 33 6f 7c 31 2e 30 2e 30 2e 37 32 31 3a 33 70 7c 31 3a 32 74 7c 38 38 38 38 3a 32 6f 7c 31 2e 30 2e 30 2e 37 32 31 3a 32 70 7c 31 3a 31 74 7c 36 36 36 36 3a 31 6f 7c 31 2e 30 2e 30 2e 37 32 31 3a 31 70 7c } //8 zf|1:lc|1:dd|1:3t|08:3o|1.0.0.721:3p|1:2t|8888:2o|1.0.0.721:2p|1:1t|6666:1o|1.0.0.721:1p|
	condition:
		((#a_03_0  & 1)*12+(#a_81_1  & 1)*8) >=20
 
}