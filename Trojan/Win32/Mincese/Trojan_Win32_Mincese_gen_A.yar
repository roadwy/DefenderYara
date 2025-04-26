
rule Trojan_Win32_Mincese_gen_A{
	meta:
		description = "Trojan:Win32/Mincese.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {c6 45 f7 64 c6 45 f8 65 c6 45 f9 78 c6 45 fa 2e c6 45 fb 64 } //2
		$a_01_1 = {eb cb 57 83 c0 1a 8b d6 33 ff eb 0b 83 ff 0f 73 0c } //2
		$a_03_2 = {c7 04 24 4a 01 00 00 ?? bf ?? ?? ?? ?? 57 c7 45 ?? 3a 0a 0d 00 } //2
		$a_01_3 = {2f 63 20 63 6f 70 79 20 2f 42 20 22 25 73 22 20 22 25 73 22 20 2f 59 } //1 /c copy /B "%s" "%s" /Y
		$a_01_4 = {77 69 6e 73 79 73 78 2e 6c 6f 67 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_03_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}