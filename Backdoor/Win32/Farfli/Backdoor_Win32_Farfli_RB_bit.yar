
rule Backdoor_Win32_Farfli_RB_bit{
	meta:
		description = "Backdoor:Win32/Farfli.RB!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c6 45 e0 44 c6 45 e1 65 c6 45 e2 66 c6 45 e3 61 c6 45 e4 75 c6 45 e6 74 c6 45 e7 2e c6 45 e8 78 c6 45 e9 6d } //1
		$a_01_1 = {0f b6 54 0e fc 30 50 ff 0f b6 14 0e 30 10 0f b6 54 0e 04 30 50 01 0f b6 54 0e 08 30 50 02 41 83 c0 04 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}