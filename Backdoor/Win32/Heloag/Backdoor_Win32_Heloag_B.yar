
rule Backdoor_Win32_Heloag_B{
	meta:
		description = "Backdoor:Win32/Heloag.B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {83 c8 80 40 88 44 3c ?? 47 83 ff 02 7c e4 } //3
		$a_00_1 = {68 65 6c 6c 6f 41 67 65 6e 74 } //1 helloAgent
		$a_00_2 = {25 64 2d 25 64 2d 25 64 2d 25 64 2d 25 64 2e 68 74 6d } //1 %d-%d-%d-%d-%d.htm
		$a_00_3 = {25 73 5c 25 64 2d 25 64 2d 25 64 2d 25 64 2d 25 64 2e 65 78 65 } //1 %s\%d-%d-%d-%d-%d.exe
	condition:
		((#a_03_0  & 1)*3+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=5
 
}