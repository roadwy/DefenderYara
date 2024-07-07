
rule Backdoor_Win32_DialerHub{
	meta:
		description = "Backdoor:Win32/DialerHub,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 0a 00 00 "
		
	strings :
		$a_01_0 = {2f 64 65 6c 2f 63 6d 62 5f } //3 /del/cmb_
		$a_01_1 = {2f 6d 69 6e 69 6c 6f 67 2e 70 68 70 } //3 /minilog.php
		$a_01_2 = {2f 6d 64 2e 70 68 70 3f 64 61 74 61 3d } //3 /md.php?data=
		$a_01_3 = {2f 64 6c 72 64 69 72 2e 68 74 6d 6c 3f 64 69 64 3d } //6 /dlrdir.html?did=
		$a_01_4 = {40 64 69 61 6c 65 72 68 75 62 2e 63 6f 6d } //6 @dialerhub.com
		$a_01_5 = {44 69 61 6c 6c 65 72 43 6c 61 73 73 } //3 DiallerClass
		$a_01_6 = {57 61 6e 61 64 6f 6f } //3 Wanadoo
		$a_01_7 = {54 2d 4f 6e 6c 69 6e 65 20 53 74 61 72 74 43 65 6e 74 65 72 } //3 T-Online StartCenter
		$a_01_8 = {41 4f 4c 20 46 72 61 6d 65 32 35 } //3 AOL Frame25
		$a_01_9 = {4f 6e 6c 69 6e 65 20 74 69 6d 65 72 } //3 Online timer
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*6+(#a_01_4  & 1)*6+(#a_01_5  & 1)*3+(#a_01_6  & 1)*3+(#a_01_7  & 1)*3+(#a_01_8  & 1)*3+(#a_01_9  & 1)*3) >=21
 
}