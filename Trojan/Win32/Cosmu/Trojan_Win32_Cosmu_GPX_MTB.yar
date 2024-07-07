
rule Trojan_Win32_Cosmu_GPX_MTB{
	meta:
		description = "Trojan:Win32/Cosmu.GPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {8f 19 1a 23 d1 31 36 d1 55 2b 89 2d 82 c3 64 3b 00 e1 a1 ff 0f 27 db a9 70 5b 1d fd 7d ae 00 c6 44 63 2a 1c f0 53 2a dc 42 ac 04 06 17 34 17 29 ea b2 03 70 f7 3e 4c 9d bc 9e 17 76 05 99 46 3c 2f 5a 17 cf a3 06 c4 28 c7 bb 78 95 32 ac d9 dc 6b 10 82 99 e9 2d ff cd 37 01 a9 d2 74 ab 4f 37 a2 3e 5d ab f6 b1 cd b9 0b 44 30 c5 f7 f7 75 ab } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}