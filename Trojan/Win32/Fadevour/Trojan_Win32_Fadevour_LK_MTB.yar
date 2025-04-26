
rule Trojan_Win32_Fadevour_LK_MTB{
	meta:
		description = "Trojan:Win32/Fadevour.LK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 c0 d4 01 00 ff 15 } //1
		$a_01_1 = {6a 36 6a 35 6a 34 6a 33 6a 32 6a 31 6a 30 6a 39 6a 38 6a 37 6a 36 6a 35 6a 34 6a 33 8b f0 6a 32 6a 31 8d 45 e4 6a 11 } //1
		$a_01_2 = {6a 04 57 ff 76 50 ff 76 34 ff d3 } //1
		$a_01_3 = {6a 04 68 00 10 00 00 ff 76 54 ff 75 fc ff d3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}