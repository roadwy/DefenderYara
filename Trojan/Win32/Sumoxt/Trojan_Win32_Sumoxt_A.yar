
rule Trojan_Win32_Sumoxt_A{
	meta:
		description = "Trojan:Win32/Sumoxt.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {6f 6b 2e 70 68 70 3f 69 3d 6d 79 74 78 74 90 01 01 2f 50 4f 50 55 50 90 00 } //1
		$a_01_1 = {69 6e 66 6f 3a 37 37 37 2f 61 62 63 33 31 72 65 63 61 6c 6c 2e 70 68 70 } //1 info:777/abc31recall.php
		$a_01_2 = {69 3d 71 69 61 6e 6d 69 6e 67 26 74 3d } //1 i=qianming&t=
		$a_01_3 = {69 3d 73 75 79 69 6e 67 26 74 3d } //1 i=suying&t=
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}