
rule Ransom_Win64_TherRansom_YAC_MTB{
	meta:
		description = "Ransom:Win64/TherRansom.YAC!MTB,SIGNATURE_TYPE_PEHSTR,0e 00 0e 00 03 00 00 "
		
	strings :
		$a_01_0 = {59 4f 55 20 48 41 56 45 20 42 45 45 4e 20 48 41 43 4b 45 44 20 42 59 20 54 48 45 46 4f 4c 4c 4f 57 45 52 53 } //10 YOU HAVE BEEN HACKED BY THEFOLLOWERS
		$a_01_1 = {41 4c 4c 20 4f 46 20 59 4f 55 52 20 46 49 4c 45 53 20 48 41 56 45 20 42 45 45 4e 20 45 4e 43 52 59 50 54 45 44 } //2 ALL OF YOUR FILES HAVE BEEN ENCRYPTED
		$a_01_2 = {57 61 6e 6e 61 43 72 79 20 2d 20 52 61 6e 73 6f 6d 77 61 72 65 } //2 WannaCry - Ransomware
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=14
 
}