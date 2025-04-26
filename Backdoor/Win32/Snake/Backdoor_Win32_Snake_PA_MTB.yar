
rule Backdoor_Win32_Snake_PA_MTB{
	meta:
		description = "Backdoor:Win32/Snake.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {03 55 f8 89 55 fc 8b 45 fc 8a 08 88 4d eb 8b 55 f4 03 55 ec 0f b6 02 0f b6 4d eb 33 c8 88 4d eb 6a 01 } //1
		$a_01_1 = {31 64 4d 33 75 75 34 6a 37 46 77 34 73 6a 6e 62 } //1 1dM3uu4j7Fw4sjnb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}