
rule Trojan_Win32_Zapchast_RG_MTB{
	meta:
		description = "Trojan:Win32/Zapchast.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4d 65 78 77 61 74 65 67 65 68 75 77 6f 77 69 68 6e 6f 67 6d 65 72 65 2e 64 6c 6c } //1 Mexwategehuwowihnogmere.dll
		$a_01_1 = {4d 65 73 6c 6f 68 6d 6f 67 75 78 2e 64 6c 6c } //1 Meslohmogux.dll
		$a_01_2 = {4c 65 78 75 73 75 6a 65 7a 75 2e 64 6c 6c } //1 Lexusujezu.dll
		$a_01_3 = {5a 61 67 65 6a 69 6d 6f 6a 6f 6a 6f 78 69 68 6f 2e 64 6c 6c } //1 Zagejimojojoxiho.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}