
rule Trojan_Win32_Koobface_K{
	meta:
		description = "Trojan:Win32/Koobface.K,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 07 00 00 "
		
	strings :
		$a_01_0 = {23 42 4c 55 45 4c 41 42 45 4c } //5 #BLUELABEL
		$a_01_1 = {61 63 74 69 6f 6e 3d 6c 64 74 6f 72 } //1 action=ldtor
		$a_01_2 = {67 65 6e 26 76 3d } //1 gen&v=
		$a_01_3 = {26 68 61 72 64 69 64 3d } //1 &hardid=
		$a_01_4 = {4b 49 4c 4c } //1 KILL
		$a_01_5 = {2f 2e 73 79 73 2e 70 68 70 } //1 /.sys.php
		$a_01_6 = {26 74 6f 74 61 6c 64 72 3d } //1 &totaldr=
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=8
 
}