
rule Trojan_Win32_OysterLoader_KAA_MTB{
	meta:
		description = "Trojan:Win32/OysterLoader.KAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {49 00 54 00 6b 00 72 00 66 00 53 00 61 00 56 00 2d 00 34 00 66 00 37 00 4b 00 77 00 64 00 66 00 6e 00 43 00 2d 00 44 00 73 00 31 00 36 00 35 00 58 00 55 00 34 00 43 00 2d 00 6c 00 48 00 36 00 52 00 39 00 70 00 6b 00 31 00 } //2 ITkrfSaV-4f7KwdfnC-Ds165XU4C-lH6R9pk1
		$a_00_1 = {54 65 73 74 } //1 Test
		$a_00_2 = {70 6f 73 74 6d 61 6e 5c 44 65 73 6b 74 6f 70 5c 4e 5a 54 5c 50 72 6f 6a 65 63 74 44 5f 63 70 70 72 65 73 74 5c 43 6c 65 61 6e 55 70 5c 52 65 6c 65 61 73 65 5c 43 6c 65 61 6e 55 70 2e 70 64 62 } //1 postman\Desktop\NZT\ProjectD_cpprest\CleanUp\Release\CleanUp.pdb
		$a_01_3 = {3b fe 72 54 8b 07 3b 45 fc 74 f2 33 c2 8b 55 fc d3 c8 8b c8 89 17 89 45 f0 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}