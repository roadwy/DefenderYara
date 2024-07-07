
rule Trojan_Win32_Evadiped_B{
	meta:
		description = "Trojan:Win32/Evadiped.B,SIGNATURE_TYPE_PEHSTR,20 00 20 00 07 00 00 "
		
	strings :
		$a_01_0 = {25 73 2f 25 73 2f 25 64 2f 25 75 2f 3f 69 64 3d 25 75 } //10 %s/%s/%d/%u/?id=%u
		$a_01_1 = {2f 77 65 62 63 6c 69 65 6e 74 2e 70 68 70 } //10 /webclient.php
		$a_01_2 = {47 00 6c 00 6f 00 62 00 61 00 6c 00 5c 00 70 00 68 00 7a 00 2e 00 72 00 71 00 5f 00 } //10 Global\phz.rq_
		$a_01_3 = {75 2e 63 6c 69 63 6b 73 63 6f 6d 70 69 6c 65 2e 63 6f 6d } //1 u.clickscompile.com
		$a_01_4 = {75 2e 75 61 74 6f 6f 6c 62 61 72 2e 63 6f 6d } //1 u.uatoolbar.com
		$a_01_5 = {6b 2e 6b 6f 6d 70 6c 65 78 61 64 2e 63 6f 6d } //1 k.komplexad.com
		$a_01_6 = {38 35 2e 31 37 2e 32 30 39 2e 33 } //1 85.17.209.3
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=32
 
}