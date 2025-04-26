
rule Trojan_Win32_Fragtor_NFE_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.NFE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {56 ff 75 f8 89 45 fc 50 89 03 89 73 10 89 7b 14 e8 26 4e 00 00 8b 45 fc 83 c4 0c 5f c6 04 06 00 5e 5b 8b e5 5d } //3
		$a_01_1 = {61 6d 6a 73 6f 6c 75 74 69 6f 6e 78 2e 70 77 2f 73 74 75 62 } //1 amjsolutionx.pw/stub
		$a_01_2 = {53 49 44 46 2e 6a 73 6f 6e } //1 SIDF.json
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}