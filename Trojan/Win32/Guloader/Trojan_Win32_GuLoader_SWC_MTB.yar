
rule Trojan_Win32_GuLoader_SWC_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.SWC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {5c 66 6f 72 65 69 67 6e 69 7a 65 2e 69 6e 69 } //1 \foreignize.ini
		$a_81_1 = {43 65 73 74 6f 64 61 2e 70 72 69 } //1 Cestoda.pri
		$a_81_2 = {66 72 73 74 65 6f 70 66 72 65 6c 73 65 2e 74 78 74 } //1 frsteopfrelse.txt
		$a_81_3 = {70 72 65 6a 75 64 69 63 69 61 6c 6e 65 73 73 2e 69 6e 69 } //1 prejudicialness.ini
		$a_81_4 = {73 65 6c 76 63 65 6e 73 75 72 65 6e 73 2e 74 78 74 } //1 selvcensurens.txt
		$a_81_5 = {5c 53 75 6c 74 61 6e 65 72 73 5c 74 65 6b 6e 6f 6c 6f 67 69 6f 6d 72 61 61 64 65 74 73 2e 62 69 6e } //1 \Sultaners\teknologiomraadets.bin
		$a_81_6 = {5c 73 61 61 70 61 73 2e 69 6e 69 } //1 \saapas.ini
		$a_81_7 = {5c 68 65 6e 6c 67 67 65 6c 73 65 72 6e 65 5c 70 61 72 76 6f 6c 69 6e 2e 6c 6e 6b } //1 \henlggelserne\parvolin.lnk
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}