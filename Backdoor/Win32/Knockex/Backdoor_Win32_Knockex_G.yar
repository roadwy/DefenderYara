
rule Backdoor_Win32_Knockex_G{
	meta:
		description = "Backdoor:Win32/Knockex.G,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 60 ff 75 08 5f 57 5e c1 c3 16 f7 d3 c0 eb 13 8b 5d 0c ac 32 c3 aa fe c3 84 c0 75 f6 61 c9 c2 08 00 } //1
		$a_01_1 = {4e 62 6c 6c 63 75 57 7b 61 71 62 77 7b 74 } //1 NbllcuW{aqbw{t
		$a_01_2 = {f9 c2 cc c9 d5 c8 c8 9d f8 d6 b2 a4 b5 a2 a8 a9 e6 97 ba a6 ca } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}