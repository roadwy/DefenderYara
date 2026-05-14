
rule Trojan_Win32_GuLoader_RDZ_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RDZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {5c 66 69 6e 6e 65 64 5c 73 75 70 65 72 73 61 6c 69 65 6e 74 5c 54 61 78 61 6d 65 74 65 72 73 79 73 74 65 6d 65 74 } //1 \finned\supersalient\Taxametersystemet
		$a_81_1 = {74 79 70 65 62 65 73 74 65 6d 6d 65 72 5c 4e 6f 6e 72 65 63 65 70 74 69 76 69 74 79 31 31 31 } //1 typebestemmer\Nonreceptivity111
		$a_81_2 = {25 6f 76 65 72 64 65 76 6f 75 74 25 5c 74 72 61 6e 73 76 65 72 73 61 6c 65 } //1 %overdevout%\transversale
		$a_81_3 = {5c 69 72 72 61 64 69 63 61 74 65 2e 6a 70 67 } //1 \irradicate.jpg
		$a_81_4 = {69 61 67 74 74 61 67 65 72 72 6f 6c 6c 65 72 6e 65 20 73 6b 67 20 61 6d 61 7a 6f 6e 61 } //1 iagttagerrollerne skg amazona
		$a_81_5 = {72 61 6d 69 65 73 } //1 ramies
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}