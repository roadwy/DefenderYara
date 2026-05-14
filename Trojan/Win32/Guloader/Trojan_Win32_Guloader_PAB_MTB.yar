
rule Trojan_Win32_Guloader_PAB_MTB{
	meta:
		description = "Trojan:Win32/Guloader.PAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_81_0 = {61 64 76 69 73 62 77 72 2e 70 6e 65 } //1 advisbwr.pne
		$a_81_1 = {48 61 6e 64 73 68 61 6b 69 6e 67 30 2e 64 69 76 } //1 Handshaking0.div
		$a_81_2 = {6c 61 76 70 72 69 73 76 61 72 65 68 75 73 65 74 73 2e 66 65 69 } //1 lavprisvarehusets.fei
		$a_81_3 = {70 72 65 61 64 61 6d 69 74 65 2e 62 69 62 } //1 preadamite.bib
		$a_81_4 = {73 6b 6e 64 73 65 6c 65 6e 73 2e 73 74 69 } //1 skndselens.sti
		$a_81_5 = {74 65 6e 64 79 70 72 2e 65 78 65 } //2 tendypr.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*2) >=7
 
}