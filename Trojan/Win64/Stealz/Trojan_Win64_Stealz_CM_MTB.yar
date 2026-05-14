
rule Trojan_Win64_Stealz_CM_MTB{
	meta:
		description = "Trojan:Win64/Stealz.CM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {39 76 42 23 6e 4c 32 40 77 51 35 24 70 58 38 7a 52 31 6d 4b 34 63 46 } //2 9vB#nL2@wQ5$pX8zR1mK4cF
		$a_01_1 = {37 68 4a 30 65 54 33 79 55 36 69 4f 39 61 53 32 64 47 35 66 48 38 } //2 7hJ0eT3yU6iO9aS2dG5fH8
		$a_01_2 = {6a 4b 31 6c 5a 34 78 43 37 76 42 30 6e 4d 33 71 57 36 74 59 39 } //2 jK1lZ4xC7vB0nM3qW6tY9
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}