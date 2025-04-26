
rule Backdoor_Win32_Dalgan_B{
	meta:
		description = "Backdoor:Win32/Dalgan.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {25 74 6d 70 25 5c 7e 61 6c 6f 74 2e 64 61 74 } //1 %tmp%\~alot.dat
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 53 79 73 49 6e 74 65 72 6e 61 6c 00 } //1
		$a_01_2 = {61 69 6c 3a 20 25 73 3a 25 64 } //1 ail: %s:%d
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}