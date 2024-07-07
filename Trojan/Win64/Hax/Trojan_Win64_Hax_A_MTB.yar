
rule Trojan_Win64_Hax_A_MTB{
	meta:
		description = "Trojan:Win64/Hax.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {65 67 3a 20 6d 73 31 36 2d 30 33 32 20 22 77 68 6f 61 6d 69 20 2f 61 6c 6c } //2 eg: ms16-032 "whoami /all
		$a_01_1 = {75 73 61 67 65 3a 20 6d 73 31 36 2d 30 33 32 20 63 6f 6d 6d 61 6e 64 } //2 usage: ms16-032 command
		$a_01_2 = {57 00 69 00 6e 00 53 00 74 00 61 00 30 00 5c 00 44 00 65 00 66 00 61 00 75 00 6c 00 74 00 } //2 WinSta0\Default
		$a_01_3 = {25 77 73 20 77 61 73 20 61 73 73 69 67 6e 65 64 } //2 %ws was assigned
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}