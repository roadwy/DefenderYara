
rule Backdoor_WinNT_Phdet_gen_B{
	meta:
		description = "Backdoor:WinNT/Phdet.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 5e 04 0f b7 d1 03 c9 2b c1 } //1
		$a_00_1 = {bf 64 86 00 00 66 3b d7 75 } //1
		$a_01_2 = {5f 00 50 00 59 00 41 00 4c 00 4f 00 41 00 44 00 } //1 _PYALOAD
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}