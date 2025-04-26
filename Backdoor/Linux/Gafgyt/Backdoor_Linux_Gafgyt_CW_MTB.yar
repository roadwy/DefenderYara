
rule Backdoor_Linux_Gafgyt_CW_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.CW!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {bf 00 2c af be 00 28 03 a0 f0 21 af bc 00 10 af c4 00 30 af c0 00 1c 8f c4 00 30 8f 99 81 78 00 } //1
		$a_00_1 = {a2 00 18 8f c4 00 50 00 60 28 21 24 06 00 0a 24 07 00 01 8f 82 80 20 00 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}
rule Backdoor_Linux_Gafgyt_CW_MTB_2{
	meta:
		description = "Backdoor:Linux/Gafgyt.CW!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {f8 ff 01 24 24 e8 a1 03 e0 ff bd 27 90 83 87 8f 00 } //1
		$a_01_1 = {19 00 44 00 12 30 00 00 10 38 00 00 21 28 a7 00 21 38 a0 00 18 80 82 8f 00 00 00 00 } //1
		$a_01_2 = {6e 3c 02 3c 72 f3 42 34 21 18 62 00 18 80 82 8f 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}