
rule Trojan_Win32_Fragtor_OCAA_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.OCAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4f 69 75 73 6f 67 73 69 75 68 41 69 68 73 67 69 75 65 68 } //1 OiusogsiuhAihsgiueh
		$a_01_1 = {56 73 61 67 66 65 75 39 69 73 68 41 73 67 75 69 68 65 } //1 Vsagfeu9ishAsguihe
		$a_01_2 = {59 6f 69 73 67 73 69 75 72 68 41 69 75 73 72 68 67 75 69 68 73 65 } //1 YoisgsiurhAiusrhguihse
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}