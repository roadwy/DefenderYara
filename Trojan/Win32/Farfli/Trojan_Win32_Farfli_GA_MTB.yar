
rule Trojan_Win32_Farfli_GA_MTB{
	meta:
		description = "Trojan:Win32/Farfli.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 03 00 00 "
		
	strings :
		$a_00_0 = {8a 08 80 f1 3d 80 c1 3d 88 08 83 c0 01 83 ee 01 75 } //10
		$a_02_1 = {5c c6 44 24 90 01 01 53 c6 44 24 90 01 01 56 c6 44 24 90 01 01 50 c6 44 24 90 01 01 37 c6 44 24 90 01 01 2e c6 44 24 90 01 01 50 c6 44 24 90 01 01 4e c6 44 24 90 01 01 47 c6 44 24 90 01 01 00 ff d5 90 00 } //10
		$a_80_2 = {53 56 50 37 2e 50 4e 47 } //SVP7.PNG  1
	condition:
		((#a_00_0  & 1)*10+(#a_02_1  & 1)*10+(#a_80_2  & 1)*1) >=21
 
}