
rule Backdoor_Win32_Fastoh_A{
	meta:
		description = "Backdoor:Win32/Fastoh.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {89 86 ac 00 00 00 b0 1b 88 44 24 04 88 44 24 05 88 44 24 06 88 44 24 07 } //1
		$a_01_1 = {8d 86 b5 00 00 00 6a 00 50 ff d7 8b 8e a8 00 00 00 } //1
		$a_01_2 = {eb 07 8b 4e 0c 8b 11 8b 02 8b 95 a8 00 00 00 8d 4c 24 1c 6a 10 51 52 89 44 24 2c ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}