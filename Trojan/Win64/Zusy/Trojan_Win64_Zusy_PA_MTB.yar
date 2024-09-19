
rule Trojan_Win64_Zusy_PA_MTB{
	meta:
		description = "Trojan:Win64/Zusy.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {64 65 73 6b 74 6f 70 2e 69 6e 69 } //1 desktop.ini
		$a_01_1 = {25 73 3d 21 21 21 20 25 73 20 57 49 4c 4c 20 4e 4f 54 20 43 4f 4e 56 45 52 54 20 21 21 21 } //1 %s=!!! %s WILL NOT CONVERT !!!
		$a_03_2 = {48 83 ec 28 48 8d 0d [0-04] e8 [0-04] 45 31 c0 31 d2 31 c9 e8 [0-04] 45 31 c0 31 d2 31 c9 e8 [0-04] 45 31 c0 31 d2 31 c9 e8 } //4
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*4) >=6
 
}