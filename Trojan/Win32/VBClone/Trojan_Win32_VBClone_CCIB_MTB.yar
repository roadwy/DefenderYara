
rule Trojan_Win32_VBClone_CCIB_MTB{
	meta:
		description = "Trojan:Win32/VBClone.CCIB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {0e dd 87 4a bd 0f 5a 09 49 b5 36 eb dd ad fe ba 62 3a 4f ad 33 99 66 cf 11 b7 0c 00 aa 00 60 d3 } //1
		$a_01_1 = {5c 00 55 00 6e 00 69 00 63 00 6f 00 72 00 6e 00 2d 00 } //1 \Unicorn-
		$a_01_2 = {63 00 6d 00 64 00 20 00 2f 00 63 00 } //1 cmd /c
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}