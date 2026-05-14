
rule Trojan_Win64_Tedy_KKB_MTB{
	meta:
		description = "Trojan:Win64/Tedy.KKB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 04 00 00 "
		
	strings :
		$a_01_0 = {48 8d 5a 01 48 89 c6 48 c1 e0 04 48 8d 3c 04 48 8b 3c d7 4c 8d 04 16 4d 8d 40 01 49 0f af f8 48 01 f9 48 89 f0 48 89 da } //20
		$a_01_1 = {4c 8d 04 b6 4e 8d 84 c4 90 04 00 00 4c 8d 0c 80 4e 8d 0c 48 49 01 f9 4d 89 0c c0 48 ff c0 } //15
		$a_01_2 = {41 83 f2 55 44 88 14 18 66 90 } //10
		$a_00_3 = {67 72 6f 77 2e 63 6f 6d 30 } //5 grow.com0
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*15+(#a_01_2  & 1)*10+(#a_00_3  & 1)*5) >=50
 
}