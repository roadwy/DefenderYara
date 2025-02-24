
rule Trojan_Win32_StealC_ASC_MTB{
	meta:
		description = "Trojan:Win32/StealC.ASC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 05 00 00 "
		
	strings :
		$a_03_0 = {51 56 68 78 53 43 00 56 56 89 35 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 56 56 ff 15 } //2
		$a_01_1 = {67 6f 6d 6f 6d 6f 6b 75 6b 6f 77 75 6d 69 70 75 73 61 78 65 76 75 } //3 gomomokukowumipusaxevu
		$a_01_2 = {77 6f 77 6f 68 61 73 61 72 65 } //1 wowohasare
		$a_01_3 = {62 61 6a 69 74 75 67 69 64 75 6e 69 6c 65 62 65 72 69 } //5 bajitugidunileberi
		$a_01_4 = {67 75 77 69 66 75 6d 65 6a 6f 74 75 77 61 66 75 6d 61 70 69 67 69 77 69 68 65 6d 6f 68 65 79 65 63 69 6b } //4 guwifumejotuwafumapigiwihemoheyecik
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*3+(#a_01_2  & 1)*1+(#a_01_3  & 1)*5+(#a_01_4  & 1)*4) >=15
 
}