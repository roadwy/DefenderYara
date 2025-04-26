
rule Backdoor_Win32_Agent_FW{
	meta:
		description = "Backdoor:Win32/Agent.FW,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 07 00 05 00 00 "
		
	strings :
		$a_01_0 = {21 64 64 6f 73 } //2 !ddos
		$a_01_1 = {3f 6e 69 63 6b 3d } //1 ?nick=
		$a_01_2 = {53 70 4c 5f 25 73 5f 5b 25 73 5d } //3 SpL_%s_[%s]
		$a_01_3 = {53 62 69 65 44 6c 6c 2e 64 6c 6c } //2 SbieDll.dll
		$a_01_4 = {77 70 61 77 35 35 26 6d 66 67 } //3 wpaw55&mfg
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*3+(#a_01_3  & 1)*2+(#a_01_4  & 1)*3) >=7
 
}