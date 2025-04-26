
rule Backdoor_Win32_Farfli_BAG_MTB{
	meta:
		description = "Backdoor:Win32/Farfli.BAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 c9 0f b7 d1 8a 14 55 [0-04] 30 14 38 40 41 3b c6 72 } //2
		$a_01_1 = {6e 6f 74 65 2e 79 6f 75 64 61 6f 2e 63 6f 6d 2f 79 77 73 2f 70 75 62 6c 69 63 2f 72 65 73 6f 75 72 63 65 } //2 note.youdao.com/yws/public/resource
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}