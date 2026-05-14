
rule Trojan_Win64_Tedy_CZ_MTB{
	meta:
		description = "Trojan:Win64/Tedy.CZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {44 31 e5 48 83 c3 01 40 88 2c 30 48 8b 84 24 } //5
		$a_03_1 = {48 89 c8 0f b6 09 4c 8d 40 ?? 48 83 c0 01 29 c1 8d 14 01 30 10 48 83 c0 01 4c 39 c0 75 } //5
		$a_01_2 = {2d 2d 6e 6f 2d 61 6e 74 69 76 6d } //1 --no-antivm
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*5+(#a_01_2  & 1)*1) >=11
 
}