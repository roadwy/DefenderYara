
rule Backdoor_Win32_Unskal_D{
	meta:
		description = "Backdoor:Win32/Unskal.D,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {75 69 6e 66 6f 3d 25 73 26 77 69 6e 3d 25 64 2e 25 64 26 62 69 74 73 3d 25 64 } //1 uinfo=%s&win=%d.%d&bits=%d
		$a_03_1 = {00 04 75 28 8b 45 fc 33 d2 b9 b0 04 00 00 f7 f1 85 d2 75 05 e8 90 01 04 6a 64 ff 15 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}