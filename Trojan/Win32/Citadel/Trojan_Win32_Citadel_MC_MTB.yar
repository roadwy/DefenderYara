
rule Trojan_Win32_Citadel_MC_MTB{
	meta:
		description = "Trojan:Win32/Citadel.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {81 e3 51 41 00 00 55 8b ec 83 ec 10 81 25 90 02 0b c7 45 90 02 08 81 05 90 02 0b c7 45 f4 90 00 } //1
		$a_01_1 = {75 62 74 7a 78 70 44 4b 42 59 49 48 52 6c 45 4b 51 42 4e 49 67 76 6d 53 5f 13 40 00 00 00 00 00 18 84 40 00 20 84 40 00 64 82 40 00 5e 72 12 dc f0 e1 49 e0 fa e1 } //1
		$a_01_2 = {b0 e1 f6 e1 bc e1 49 e0 bd e1 95 24 92 25 82 35 83 36 f3 06 f0 07 b2 e1 fd e1 49 e0 fd e1 b5 e1 c7 e1 b0 e1 e0 e1 bc e1 49 e0 bd } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}