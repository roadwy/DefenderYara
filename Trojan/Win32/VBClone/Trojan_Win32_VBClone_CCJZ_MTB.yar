
rule Trojan_Win32_VBClone_CCJZ_MTB{
	meta:
		description = "Trojan:Win32/VBClone.CCJZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {ff cc 31 00 04 8c 2d 5b 5e b1 87 3b 43 99 } //6
		$a_01_1 = {ba 62 3a 4f ad 33 99 66 cf 11 b7 0c 00 aa 00 60 d3 93 } //4
	condition:
		((#a_01_0  & 1)*6+(#a_01_1  & 1)*4) >=10
 
}