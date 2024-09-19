
rule Trojan_Win64_Sminager_AA_MTB{
	meta:
		description = "Trojan:Win64/Sminager.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {50 61 74 68 3d 25 41 50 50 44 41 54 41 25 2f 53 65 74 70 6f 6f 6c 0d 0a 53 65 74 75 70 3d 41 50 50 2e 76 62 73 0d 0a 53 69 6c 65 6e 74 3d 32 } //10
		$a_01_1 = {79 6f 75 20 61 67 72 65 65 20 74 6f 20 75 73 65 20 74 68 65 20 72 65 73 6f 75 72 63 65 73 20 6f 66 20 79 6f 75 72 20 50 43 20 28 43 50 55 20 61 6e 64 20 2f 20 6f 72 20 67 72 61 70 68 69 63 73 20 63 61 72 64 20 6c 6f 61 64 20 69 73 20 70 6f 73 73 69 62 6c 65 20 66 72 6f 6d 20 35 25 20 74 6f 20 31 30 30 25 29 } //10 you agree to use the resources of your PC (CPU and / or graphics card load is possible from 5% to 100%)
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}