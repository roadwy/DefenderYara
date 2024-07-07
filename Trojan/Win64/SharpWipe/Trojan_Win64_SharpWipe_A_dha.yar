
rule Trojan_Win64_SharpWipe_A_dha{
	meta:
		description = "Trojan:Win64/SharpWipe.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {c7 45 d4 43 00 3a 00 c7 45 d8 5c 00 57 00 c7 45 dc 69 00 6e 00 c7 45 e0 64 00 6f 00 c7 45 e4 77 00 73 00 c7 45 e8 5c 00 69 00 c7 45 ec 6d 00 67 00 c7 45 f0 2e 00 69 00 c7 45 f4 73 00 6f 00 } //1
		$a_01_1 = {c7 45 98 25 00 73 00 c7 45 9c 20 00 2d 00 c7 45 a0 61 00 63 00 c7 45 a4 63 00 65 00 c7 45 a8 70 00 74 00 c7 45 ac 65 00 75 00 c7 45 b0 6c 00 61 00 c7 45 b4 20 00 2d 00 } //1
		$a_01_2 = {c7 45 b8 72 00 20 00 c7 45 bc 2d 00 73 00 c7 45 c0 20 00 2d 00 c7 45 c4 71 00 20 00 c7 45 c8 25 00 63 00 c7 45 cc 3a 00 5c 00 c7 45 d0 2a 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}