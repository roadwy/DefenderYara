
rule TrojanSpy_Win32_Delf_BW{
	meta:
		description = "TrojanSpy:Win32/Delf.BW,SIGNATURE_TYPE_PEHSTR,06 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {65 32 4b 65 79 50 72 65 73 73 } //1 e2KeyPress
		$a_01_1 = {65 6d 61 69 6c 3d 6c 31 6e 35 78 40 69 67 2e 63 6f 6d 2e 62 72 } //1 email=l1n5x@ig.com.br
		$a_01_2 = {66 72 6f 6d 3d 62 79 65 40 6f 69 2e 63 6f 6d } //1 from=bye@oi.com
		$a_01_3 = {66 72 6f 6d 3d 6f 6c 61 40 6f 69 2e 63 6f 6d } //1 from=ola@oi.com
		$a_01_4 = {73 75 62 6a 65 63 74 3d } //1 subject=
		$a_01_5 = {68 74 74 70 3a 2f 2f 77 77 77 2e 63 6c 75 62 68 69 66 69 2e 6e 6c 2f 65 6e 76 69 61 2e 70 68 70 } //1 http://www.clubhifi.nl/envia.php
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}