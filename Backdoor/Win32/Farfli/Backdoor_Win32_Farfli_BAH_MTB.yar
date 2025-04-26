
rule Backdoor_Win32_Farfli_BAH_MTB{
	meta:
		description = "Backdoor:Win32/Farfli.BAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {8a 14 01 80 c2 66 80 f2 fe 88 14 01 41 3b 4c 24 08 7c } //2
		$a_01_1 = {25 73 2e 65 78 65 } //1 %s.exe
		$a_01_2 = {63 25 63 25 63 25 63 25 63 25 63 2e 65 78 65 } //1 c%c%c%c%c%c.exe
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}