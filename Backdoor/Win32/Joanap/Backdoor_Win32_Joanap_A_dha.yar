
rule Backdoor_Win32_Joanap_A_dha{
	meta:
		description = "Backdoor:Win32/Joanap.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_01_0 = {69 61 6d 73 6f 72 72 79 21 40 31 32 33 34 35 36 37 } //10 iamsorry!@1234567
		$a_01_1 = {30 31 62 42 48 6a 40 32 33 74 24 34 36 25 67 68 } //1 01bBHj@23t$46%gh
		$a_01_2 = {21 40 23 24 25 5e 26 2a } //1 !@#$%^&*
		$a_01_3 = {25 25 73 5c 25 25 73 25 25 30 25 64 64 2e 25 25 73 } //1 %%s\%%s%%0%dd.%%s
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=11
 
}