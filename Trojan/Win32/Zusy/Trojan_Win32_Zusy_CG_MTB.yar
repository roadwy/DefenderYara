
rule Trojan_Win32_Zusy_CG_MTB{
	meta:
		description = "Trojan:Win32/Zusy.CG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_01_0 = {41 66 67 61 6f 65 69 70 30 66 67 61 6a 33 39 30 67 6a } //2 Afgaoeip0fgaj390gj
		$a_01_1 = {42 73 67 69 6f 73 6a 67 6f 69 70 73 34 6a 67 39 73 34 6a 68 67 } //2 Bsgiosjgoips4jg9s4jhg
		$a_01_2 = {4f 50 70 6f 61 6f 69 66 67 61 65 69 6f 67 66 61 65 69 6f 67 68 } //2 OPpoaoifgaeiogfaeiogh
		$a_01_3 = {55 6f 69 73 67 6f 69 61 73 65 67 6f 69 65 61 73 67 69 73 65 61 6a 67 69 } //2 Uoisgoiasegoieasgiseajgi
		$a_01_4 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } //1 WaitForSingleObject
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1) >=9
 
}