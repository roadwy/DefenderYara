
rule Backdoor_Win32_Idicaf_gen_B{
	meta:
		description = "Backdoor:Win32/Idicaf.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {8b 44 24 0c 6a ?? 5f 8d 0c 06 8b c6 99 f7 ff b0 ?? 2a c2 00 01 46 } //2
		$a_00_1 = {70 6c 75 67 5f 6b 65 79 6c 6f 67 } //1 plug_keylog
		$a_03_2 = {5b 53 53 44 54 [0-01] 52 69 6e 67 30 [0-04] 3a 5d 20 25 64 } //1
	condition:
		((#a_02_0  & 1)*2+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}