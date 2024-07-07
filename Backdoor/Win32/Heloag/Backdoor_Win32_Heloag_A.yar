
rule Backdoor_Win32_Heloag_A{
	meta:
		description = "Backdoor:Win32/Heloag.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {83 c8 80 40 88 04 3e 46 83 fe 64 7c e5 be 02 00 00 00 } //3
		$a_00_1 = {68 65 6c 6c 6f 41 67 65 6e 74 } //1 helloAgent
		$a_00_2 = {25 64 2d 25 64 2d 25 64 2d 25 64 2d 25 64 2e 68 74 6d } //1 %d-%d-%d-%d-%d.htm
		$a_00_3 = {25 73 5c 25 64 2d 25 64 2d 25 64 2d 25 64 2d 25 64 2e 65 78 65 } //1 %s\%d-%d-%d-%d-%d.exe
		$a_03_4 = {68 89 13 00 00 68 90 01 04 8b 48 10 51 e8 90 00 } //1
	condition:
		((#a_01_0  & 1)*3+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}