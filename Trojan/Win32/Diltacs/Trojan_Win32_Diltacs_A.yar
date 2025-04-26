
rule Trojan_Win32_Diltacs_A{
	meta:
		description = "Trojan:Win32/Diltacs.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {68 69 74 73 3f 61 63 74 3d 34 26 61 69 64 3d } //1 hits?act=4&aid=
		$a_01_1 = {75 73 65 72 6e 61 6d 65 3d } //1 username=
		$a_01_2 = {70 61 73 73 77 6f 72 64 3d } //1 password=
		$a_01_3 = {61 64 73 6c 6e 61 6d 65 3d } //1 adslname=
		$a_01_4 = {61 64 73 6c 61 75 74 6f 3d } //1 adslauto=
		$a_01_5 = {4d 69 73 73 57 68 6f 5f 4f 4b } //1 MissWho_OK
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}