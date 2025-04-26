
rule Backdoor_Win32_ParalaxRat_Q_MTB{
	meta:
		description = "Backdoor:Win32/ParalaxRat.Q!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 c8 33 c0 01 4e 04 40 c7 44 96 0c 02 00 00 00 } //5
		$a_01_1 = {8b 55 08 33 c0 8b 4d 0c c7 44 8a 0c 02 00 00 00 ff 42 04 40 89 44 8a 0c } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}