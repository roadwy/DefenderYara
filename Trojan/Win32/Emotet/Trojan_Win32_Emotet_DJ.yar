
rule Trojan_Win32_Emotet_DJ{
	meta:
		description = "Trojan:Win32/Emotet.DJ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {54 39 62 58 4d 71 65 76 3d 39 2d 79 55 50 4a 5f 49 32 32 2e 70 64 62 } //01 00  T9bXMqev=9-yUPJ_I22.pdb
		$a_01_1 = {49 00 6e 00 74 00 65 00 72 00 6e 00 61 00 6c 00 4e 00 61 00 6d 00 65 00 00 00 6b 00 62 00 64 00 62 00 75 00 20 00 28 00 33 00 2e 00 31 00 33 00 29 00 00 00 6e 00 48 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Emotet_DJ_2{
	meta:
		description = "Trojan:Win32/Emotet.DJ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {72 74 6a 68 65 57 52 4a 4b 65 79 57 59 40 23 79 68 4a 74 72 6a 45 52 2e 70 64 62 } //01 00  rtjheWRJKeyWY@#yhJtrjER.pdb
		$a_01_1 = {49 00 6e 00 74 00 65 00 72 00 6e 00 61 00 6c 00 4e 00 61 00 6d 00 65 00 00 00 50 00 72 00 69 00 6e 00 74 00 49 00 73 00 6f 00 6c 00 61 00 74 00 69 00 6f 00 6e 00 48 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 } //00 00 
	condition:
		any of ($a_*)
 
}