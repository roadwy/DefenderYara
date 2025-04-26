
rule Backdoor_Win32_Fledrots_A{
	meta:
		description = "Backdoor:Win32/Fledrots.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {68 70 f1 00 00 68 12 01 00 00 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? eb cd } //2
		$a_01_1 = {70 69 6e 67 2e 70 68 70 } //1 ping.php
		$a_01_2 = {69 6d 67 6f 6e 00 } //1 浩潧n
		$a_01_3 = {26 72 73 74 3d 31 } //1 &rst=1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}