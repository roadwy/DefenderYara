
rule Trojan_Win64_Mikey_LMC_MTB{
	meta:
		description = "Trojan:Win64/Mikey.LMC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 03 00 00 "
		
	strings :
		$a_01_0 = {4c 8b 40 30 4c 89 85 18 02 00 00 49 63 40 3c 4a 8b 8c 00 88 00 00 00 44 8b c9 48 89 8d 78 02 00 00 4d 03 c8 4c 89 8d 20 02 00 00 48 c1 e9 20 89 8d 10 02 00 00 4d 3b c8 } //20
		$a_01_1 = {0f be c8 41 33 c8 44 69 c1 43 01 00 00 0f b6 02 48 8d 52 01 84 c0 } //10
		$a_01_2 = {4c 89 9d c0 00 00 00 49 8b db 48 89 9d c8 00 00 00 49 8b c3 4c 8b 40 30 4c 89 45 68 49 63 40 3c 4a 8b 8c 00 88 00 00 00 44 8b d1 48 89 4d 10 4d 03 d0 4c 89 55 70 48 c1 e9 20 89 4d 60 4d 3b d0 } //5
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10+(#a_01_2  & 1)*5) >=35
 
}