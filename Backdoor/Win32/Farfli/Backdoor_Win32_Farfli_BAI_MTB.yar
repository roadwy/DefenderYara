
rule Backdoor_Win32_Farfli_BAI_MTB{
	meta:
		description = "Backdoor:Win32/Farfli.BAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 06 00 00 "
		
	strings :
		$a_03_0 = {8b 4d 08 8a 14 11 32 94 45 04 ff ff ff 8b 85 f8 fe ff ff 25 90 02 04 8b 4d 08 88 14 01 66 8b 95 fc fe ff ff 66 83 c2 01 66 89 95 fc fe ff ff e9 90 00 } //3
		$a_01_1 = {78 75 69 2e 70 74 6c 6f 67 69 6e 32 2e 71 71 2e 63 6f 6d } //2 xui.ptlogin2.qq.com
		$a_01_2 = {25 73 2e 65 78 65 } //2 %s.exe
		$a_01_3 = {25 73 2e 64 6d 70 } //2 %s.dmp
		$a_01_4 = {5b 53 63 72 6f 6c 6c 20 4c 6f 63 6b 5d } //1 [Scroll Lock]
		$a_01_5 = {5b 50 72 69 6e 74 20 53 63 72 65 65 6e 5d } //1 [Print Screen]
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=11
 
}