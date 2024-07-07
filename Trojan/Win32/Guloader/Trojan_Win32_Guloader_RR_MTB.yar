
rule Trojan_Win32_Guloader_RR_MTB{
	meta:
		description = "Trojan:Win32/Guloader.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_81_0 = {53 65 53 68 75 74 64 6f 77 6e 50 72 69 76 69 6c 65 67 65 } //1 SeShutdownPrivilege
		$a_81_1 = {49 6e 69 74 69 61 74 65 53 68 75 74 64 6f 77 6e 57 } //1 InitiateShutdownW
		$a_00_2 = {46 00 72 00 65 00 6e 00 61 00 74 00 61 00 65 00 20 00 42 00 69 00 6f 00 65 00 6e 00 65 00 72 00 67 00 69 00 20 00 52 00 65 00 63 00 68 00 61 00 62 00 69 00 74 00 69 00 73 00 6d 00 } //2 Frenatae Bioenergi Rechabitism
		$a_81_3 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_00_2  & 1)*2+(#a_81_3  & 1)*1) >=5
 
}