
rule HackTool_Win64_Injector_PAHB_MTB{
	meta:
		description = "HackTool:Win64/Injector.PAHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 06 00 00 "
		
	strings :
		$a_01_0 = {5c 49 41 6d 41 6e 74 69 6d 61 6c 77 61 72 65 2e 70 64 62 } //5 \IAmAntimalware.pdb
		$a_01_1 = {6c 61 75 6e 63 68 50 72 6f 74 65 63 74 65 64 } //1 launchProtected
		$a_01_2 = {63 65 72 74 44 61 74 61 } //1 certData
		$a_01_3 = {43 65 72 74 41 64 64 43 65 72 74 69 66 69 63 61 74 65 43 6f 6e 74 65 78 74 54 6f 53 74 6f 72 65 } //2 CertAddCertificateContextToStore
		$a_01_4 = {73 69 64 49 6e 66 6f } //1 sidInfo
		$a_01_5 = {73 6f 75 72 63 65 4b 65 79 50 61 74 68 } //1 sourceKeyPath
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=11
 
}