
rule Trojan_Win64_Midie_MK_MTB{
	meta:
		description = "Trojan:Win64/Midie.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 63 ca 8b c2 48 c1 e1 05 4e 39 1c 11 41 0f 45 c0 ff c2 44 8b c0 41 3b d1 } //20
		$a_01_1 = {c7 45 cc 65 6c 33 32 c7 45 d0 2e 64 6c 6c c6 45 d4 00 c7 45 e8 6e 45 6e 74 66 c7 45 ec 72 79 c6 45 ee } //15
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*15) >=35
 
}