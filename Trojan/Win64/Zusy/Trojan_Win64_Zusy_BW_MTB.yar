
rule Trojan_Win64_Zusy_BW_MTB{
	meta:
		description = "Trojan:Win64/Zusy.BW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {55 69 73 67 6f 73 65 69 6f 69 6a 65 67 69 6f 77 65 41 6f 73 6a 65 67 68 69 6f 65 73 6a 68 } //2 UisgoseioijegioweAosjeghioesjh
		$a_01_1 = {59 69 6f 70 72 67 6f 69 70 77 72 51 6f 6f 67 6a 69 73 65 6a 67 69 65 73 } //2 YioprgoipwrQoogjisejgies
		$a_01_2 = {6b 66 6c 67 73 6b 72 67 6f 70 73 65 6f 70 69 68 73 65 6a 68 69 6a } //2 kflgskrgopseopihsejhij
		$a_01_3 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } //1 WaitForSingleObject
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=7
 
}