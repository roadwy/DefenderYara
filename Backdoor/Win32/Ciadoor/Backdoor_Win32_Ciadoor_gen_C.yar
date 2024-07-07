
rule Backdoor_Win32_Ciadoor_gen_C{
	meta:
		description = "Backdoor:Win32/Ciadoor.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,08 00 07 00 05 00 00 "
		
	strings :
		$a_01_0 = {5a 68 10 c4 02 11 68 14 c4 02 11 52 e9 e7 ff ff ff } //6
		$a_01_1 = {78 78 2e 64 6c 6c 00 } //1
		$a_01_2 = {1b 92 02 fb 30 1c 56 1f 00 1f f4 00 2b 56 fe f5 00 00 00 00 43 50 ff 04 50 ff f4 ff 2b 4e ff 0a } //2
		$a_01_3 = {1b d1 02 fb 30 1c 49 2b 00 24 f5 01 00 00 00 76 14 01 2e e0 fe 40 f4 07 fb fd fd c7 50 ff 7f 0c } //2
		$a_01_4 = {10 20 07 0a fe 2f 50 02 00 02 00 02 00 03 13 f8 04 c8 b4 ff 0b 80 01 00 00 19 68 ff 08 68 ff 0d } //2
	condition:
		((#a_01_0  & 1)*6+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=7
 
}