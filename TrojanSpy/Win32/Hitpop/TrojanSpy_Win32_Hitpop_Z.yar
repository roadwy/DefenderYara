
rule TrojanSpy_Win32_Hitpop_Z{
	meta:
		description = "TrojanSpy:Win32/Hitpop.Z,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_01_0 = {41 56 50 2e 42 75 74 74 6f 6e } //1 AVP.Button
		$a_01_1 = {77 69 6e 6c 6b 2e 69 6e 69 } //1 winlk.ini
		$a_01_2 = {6d 79 64 6f 77 6e } //1 mydown
		$a_01_3 = {68 69 74 70 6f 70 } //1 hitpop
		$a_01_4 = {73 79 73 64 6e 2e 69 6e 69 } //1 sysdn.ini
		$a_01_5 = {6d 64 35 5f 76 65 72 } //1 md5_ver
		$a_01_6 = {3f 72 65 67 3d } //1 ?reg=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=6
 
}