
rule Trojan_Win32_NSISInject_BE_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.BE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 75 74 69 6c 62 6a 65 6c 69 67 68 65 64 65 72 } //1 Software\utilbjeligheder
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 45 78 74 72 61 74 72 6f 70 69 63 61 6c 5c 46 72 65 6d 6d 65 64 73 70 72 6f 67 73 75 6e 64 65 72 76 69 73 6e 69 6e 67 65 6e } //1 Software\Extratropical\Fremmedsprogsundervisningen
		$a_01_2 = {55 6e 64 65 72 67 72 61 64 75 61 74 65 64 6f 6d 5c 70 65 72 73 6f 6e 6b 72 65 64 73 2e 44 65 6d } //1 Undergraduatedom\personkreds.Dem
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 43 6f 73 65 61 73 6f 6e 61 6c 5c 41 67 67 72 61 6e 64 69 7a 65 6d 65 6e 74 5c 4d 65 73 6f 73 74 65 72 6e 61 6c 5c 54 68 65 6f 72 69 73 65 72 73 } //1 Software\Coseasonal\Aggrandizement\Mesosternal\Theorisers
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}