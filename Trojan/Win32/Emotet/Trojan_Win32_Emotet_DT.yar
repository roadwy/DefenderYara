
rule Trojan_Win32_Emotet_DT{
	meta:
		description = "Trojan:Win32/Emotet.DT,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {6c 49 46 64 72 47 6b 6d 42 65 50 73 73 2e 70 64 62 } //1 lIFdrGkmBePss.pdb
		$a_01_1 = {2f 64 51 57 50 49 43 6c 5f 48 75 64 65 31 76 2e 70 64 62 } //1 /dQWPICl_Hude1v.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}
rule Trojan_Win32_Emotet_DT_2{
	meta:
		description = "Trojan:Win32/Emotet.DT,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {41 63 69 64 33 44 69 5a 61 75 74 6f 2d 75 70 64 61 74 69 6e 67 50 77 61 73 61 } //1 Acid3DiZauto-updatingPwasa
		$a_01_1 = {4d 61 79 6a 65 41 54 68 65 74 6f 79 6f 74 61 49 6f 66 32 30 30 38 } //1 MayjeAThetoyotaIof2008
		$a_01_2 = {73 5a 6c 61 75 6e 63 68 65 64 66 75 63 6b 6f 66 66 6a 7a 47 4d 41 77 68 69 63 68 } //1 sZlaunchedfuckoffjzGMAwhich
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}