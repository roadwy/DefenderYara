
rule Trojan_Win32_Yektel_C{
	meta:
		description = "Trojan:Win32/Yektel.C,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {80 3e c3 75 [0-05] ff d6 } //1
		$a_00_1 = {4a 03 0c 24 80 3a 90 75 } //1
		$a_00_2 = {01 f8 c2 08 00 60 } //1
		$a_00_3 = {9d 83 f8 00 74 05 88 02 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}