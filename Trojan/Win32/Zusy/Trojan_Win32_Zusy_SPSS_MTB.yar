
rule Trojan_Win32_Zusy_SPSS_MTB{
	meta:
		description = "Trojan:Win32/Zusy.SPSS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_01_0 = {6a 6d 77 65 63 7a 62 78 63 76 6a 73 69 } //2 jmweczbxcvjsi
		$a_01_1 = {6d 69 67 6a 74 73 75 75 6b 6a 76 74 } //2 migjtsuukjvt
		$a_01_2 = {70 7a 76 6d 6b 63 6f 75 79 76 71 6b } //2 pzvmkcouyvqk
		$a_01_3 = {76 79 68 62 69 6f 7a 7a 72 77 } //2 vyhbiozzrw
		$a_01_4 = {7a 6a 6a 63 72 6d 62 65 68 6f 61 6b 6d } //1 zjjcrmbehoakm
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1) >=9
 
}