
rule Trojan_Win32_Guloader_SPBI_MTB{
	meta:
		description = "Trojan:Win32/Guloader.SPBI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 07 00 00 "
		
	strings :
		$a_01_0 = {49 6e 74 65 72 76 69 65 77 74 65 6b 6e 69 6b 6b 65 72 6e 65 2e 6c 61 6e } //2 Interviewteknikkerne.lan
		$a_01_1 = {73 74 61 68 6c 69 61 6e 69 73 6d 2e 72 65 67 } //1 stahlianism.reg
		$a_01_2 = {42 65 76 61 72 65 6c 73 65 2e 6c 61 67 } //1 Bevarelse.lag
		$a_01_3 = {73 74 72 6f 70 68 61 6e 74 68 75 73 2e 74 78 74 } //1 strophanthus.txt
		$a_01_4 = {66 72 61 66 61 6c 64 65 6e 65 2e 70 6f 73 } //1 frafaldene.pos
		$a_01_5 = {62 72 65 6d 69 61 2e 73 75 72 } //1 bremia.sur
		$a_01_6 = {54 69 61 6e 65 2e 62 61 6c } //1 Tiane.bal
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=8
 
}