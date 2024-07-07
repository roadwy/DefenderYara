
rule Backdoor_Win32_Wavipeg_A{
	meta:
		description = "Backdoor:Win32/Wavipeg.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {66 74 2f 73 69 2e 70 68 70 3f } //1 ft/si.php?
		$a_01_1 = {61 76 70 00 65 73 65 74 00 65 67 75 69 } //1
		$a_01_2 = {25 73 3d 64 64 6f 73 26 63 6f 6d 70 3d 25 73 } //1 %s=ddos&comp=%s
		$a_01_3 = {26 63 6f 6d 70 3d 25 73 26 65 78 74 3d } //1 &comp=%s&ext=
		$a_01_4 = {3c 42 4b 3e 00 3c 44 4f 57 4e 3e } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}