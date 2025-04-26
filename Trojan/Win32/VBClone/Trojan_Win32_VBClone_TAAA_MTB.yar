
rule Trojan_Win32_VBClone_TAAA_MTB{
	meta:
		description = "Trojan:Win32/VBClone.TAAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {0e dd 87 4a bd 0f 5a 09 49 b5 36 eb dd ad fe ba 62 3a 4f ad 33 99 66 cf 11 b7 0c 00 aa 00 60 d3 } //3
		$a_01_1 = {5c 00 55 00 6e 00 69 00 63 00 6f 00 72 00 6e 00 2d 00 } //1 \Unicorn-
		$a_01_2 = {63 00 20 00 72 00 65 00 6e 00 61 00 6d 00 65 00 } //1 c rename
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}