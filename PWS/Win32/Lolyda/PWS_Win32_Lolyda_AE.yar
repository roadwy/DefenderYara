
rule PWS_Win32_Lolyda_AE{
	meta:
		description = "PWS:Win32/Lolyda.AE,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {7a 6f 6e 65 3d 25 73 26 } //1 zone=%s&
		$a_00_1 = {6e 61 6d 65 3d 25 73 26 } //1 name=%s&
		$a_00_2 = {73 65 72 76 65 72 3d 25 73 26 } //1 server=%s&
		$a_00_3 = {66 6f 6e 74 73 5c 67 74 68 } //1 fonts\gth
		$a_01_4 = {c6 06 e9 2b c6 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}