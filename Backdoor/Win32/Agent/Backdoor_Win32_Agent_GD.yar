
rule Backdoor_Win32_Agent_GD{
	meta:
		description = "Backdoor:Win32/Agent.GD,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {f7 e9 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 } //1
		$a_00_1 = {5c 53 79 73 74 65 6d 5c 61 64 6f 5c 6d 73 61 64 6f 72 31 35 } //1 \System\ado\msador15
		$a_00_2 = {61 76 30 33 30 39 5c 61 76 30 33 31 30 5c 6e 65 77 20 6a 6b 32 30 30 39 5c } //1 av0309\av0310\new jk2009\
		$a_00_3 = {73 79 73 74 65 6d 33 32 2e 65 78 65 } //1 system32.exe
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}