
rule TrojanDownloader_O97M_Qakbot_QAA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.QAA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 67 48 6e 62 66 4b 74 5c } //1 C:\gHnbfKt\
		$a_01_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
		$a_01_2 = {63 4f 68 74 66 42 6a } //1 cOhtfBj
		$a_01_3 = {68 74 74 70 3a 2f 2f 6b 6c 69 6b 73 69 6e 69 2e 77 65 62 2e 69 64 2f 64 73 2f 30 36 31 32 32 30 2e 67 69 66 } //1 http://kliksini.web.id/ds/061220.gif
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}