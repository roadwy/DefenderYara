
rule Trojan_Win64_PrintNightmare_A_MTB{
	meta:
		description = "Trojan:Win64/PrintNightmare.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {45 33 c9 89 44 24 48 48 89 44 24 64 48 8d 1d 90 01 04 89 44 24 6c 4c 8d 44 24 38 0f 57 c0 48 89 5c 24 38 48 8d 05 90 01 04 c7 44 24 60 00 00 01 00 41 8d 51 01 48 89 44 24 40 33 c9 f3 0f 7f 44 24 50 ff 15 90 01 04 4c 8d 4c 24 30 48 89 5c 24 30 41 b8 03 00 00 00 c7 44 24 20 01 00 00 00 48 8d 15 f5 da 02 00 33 c9 ff 15 1d 90 00 } //2
		$a_01_1 = {6e 69 67 68 74 6d 61 72 65 } //2 nightmare
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}