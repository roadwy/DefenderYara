
rule Trojan_Win32_GuLoader_REH_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.REH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {67 6c 65 6d 6d 65 62 67 65 72 5c 62 65 6c 74 6c 65 73 73 } //1 glemmebger\beltless
		$a_81_1 = {75 6e 6d 65 61 73 75 72 61 62 6c 65 6e 65 73 73 5c 61 66 66 61 62 6c 65 5c 77 69 61 74 74 } //1 unmeasurableness\affable\wiatt
		$a_81_2 = {5c 73 65 76 69 6c 6c 69 61 6e 5c 61 73 74 65 72 69 78 69 73 2e 69 6e 69 } //1 \sevillian\asterixis.ini
		$a_81_3 = {5c 75 6c 74 72 61 6d 61 78 69 6d 61 6c 5c 73 6d 6c 64 65 74 73 2e 64 6c 6c } //1 \ultramaximal\smldets.dll
		$a_81_4 = {25 73 69 74 61 72 65 6e 73 25 5c 64 69 6f 72 61 6d 69 63 } //1 %sitarens%\dioramic
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}