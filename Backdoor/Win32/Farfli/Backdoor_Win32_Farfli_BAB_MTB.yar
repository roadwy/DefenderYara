
rule Backdoor_Win32_Farfli_BAB_MTB{
	meta:
		description = "Backdoor:Win32/Farfli.BAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {27 a9 92 19 5b 97 98 8b 5a 21 81 b8 6e df 55 03 c9 81 5b 21 81 b2 cf 54 ed 97 b6 10 cd 96 75 } //2
		$a_01_1 = {31 66 84 dd 7a 54 fd f7 ac 7a de a1 b5 29 67 5f ed 91 09 60 ff 49 92 19 53 2b c9 fd fa 7b } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}