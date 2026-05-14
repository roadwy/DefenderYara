
rule Trojan_Win32_RemcosRAT_RVA_MTB{
	meta:
		description = "Trojan:Win32/RemcosRAT.RVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {61 66 72 69 63 61 6e 74 68 72 6f 70 75 73 20 76 65 72 73 69 66 69 63 65 72 69 6e 67 65 6e } //1 africanthropus versificeringen
		$a_81_1 = {67 61 73 74 72 6f 70 74 6f 73 69 61 } //1 gastroptosia
		$a_81_2 = {74 72 73 6b 65 73 74 65 73 20 72 75 73 74 72 64 65 } //1 trskestes rustrde
		$a_81_3 = {6c 61 6e 64 67 72 65 76 65 6e 20 6c 6f 69 6d 6f 6c 6f 67 79 } //1 landgreven loimology
		$a_81_4 = {73 65 73 73 69 6c 69 74 79 20 70 69 6c 73 6e 65 72 73 } //1 sessility pilsners
		$a_81_5 = {75 6e 64 65 72 73 68 6f 74 2e 65 78 65 } //1 undershot.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}