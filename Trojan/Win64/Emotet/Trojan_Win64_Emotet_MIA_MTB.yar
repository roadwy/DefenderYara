
rule Trojan_Win64_Emotet_MIA_MTB{
	meta:
		description = "Trojan:Win64/Emotet.MIA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {78 79 75 7a } //1 xyuz
		$a_81_1 = {53 43 2e 45 58 45 } //1 SC.EXE
		$a_81_2 = {79 61 68 61 76 53 6f 64 75 6b 75 2e 74 78 74 } //1 yahavSoduku.txt
		$a_81_3 = {42 6f 61 72 64 20 6e 75 6d 62 65 72 3a } //1 Board number:
		$a_81_4 = {44 6c 6c 31 2e 64 6c 6c } //1 Dll1.dll
		$a_81_5 = {75 2e 74 78 74 } //1 u.txt
		$a_81_6 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}