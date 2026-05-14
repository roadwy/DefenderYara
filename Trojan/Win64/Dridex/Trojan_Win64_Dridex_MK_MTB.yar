
rule Trojan_Win64_Dridex_MK_MTB{
	meta:
		description = "Trojan:Win64/Dridex.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 0f 29 06 45 89 d2 45 89 d7 41 89 da 45 89 d4 41 89 fa 45 89 d5 49 c1 e5 04 4c 01 ea 49 c1 e4 03 4c 01 e2 49 c1 e7 02 4c 01 fa 44 8b 12 45 89 c0 44 89 c2 } //20
		$a_01_1 = {48 8b 44 24 28 8a 4c 24 3f 31 d2 41 89 d0 4c 8d 0d 54 10 00 00 45 8a 14 01 48 83 c0 01 44 38 d1 48 89 44 24 20 4c 89 84 24 90 } //15
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*15) >=35
 
}