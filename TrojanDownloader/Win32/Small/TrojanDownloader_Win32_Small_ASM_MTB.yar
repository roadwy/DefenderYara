
rule TrojanDownloader_Win32_Small_ASM_MTB{
	meta:
		description = "TrojanDownloader:Win32/Small.ASM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {04 e2 23 03 00 24 5a 4c 36 4d d3 34 3e 32 26 1a 90 23 69 9a a6 59 a4 b2 c0 } //1
		$a_01_1 = {66 00 72 00 65 00 65 00 64 00 61 00 74 00 61 00 76 00 65 00 72 00 69 00 66 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 2e 00 63 00 6f 00 6d 00 } //2 freedataverification.com
		$a_01_2 = {73 00 65 00 6c 00 6c 00 6d 00 61 00 6b 00 65 00 72 00 73 00 2e 00 63 00 6f 00 6d 00 } //3 sellmakers.com
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*3) >=6
 
}