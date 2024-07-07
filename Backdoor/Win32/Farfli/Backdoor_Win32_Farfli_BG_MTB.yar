
rule Backdoor_Win32_Farfli_BG_MTB{
	meta:
		description = "Backdoor:Win32/Farfli.BG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {33 c9 8a 1c 38 8b d1 81 e2 ff ff 00 00 8a 54 54 0c 32 da 41 88 1c 38 40 3b c6 72 } //2
		$a_01_1 = {67 69 74 65 65 2e 63 6f 6d 2f 2f 73 74 61 6e 64 61 72 2f 2f 70 6c 75 67 2d 69 6e 2d 32 2f 2f 72 61 77 2f 6d 61 73 74 65 72 2f 2f 53 65 6e } //1 gitee.com//standar//plug-in-2//raw/master//Sen
		$a_01_2 = {68 6c 6f 77 6f 72 6c 64 2e 63 6e } //1 hloworld.cn
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}