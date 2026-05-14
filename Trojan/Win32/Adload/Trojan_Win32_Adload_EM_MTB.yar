
rule Trojan_Win32_Adload_EM_MTB{
	meta:
		description = "Trojan:Win32/Adload.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_81_0 = {50 44 46 2d 58 43 68 61 6e 67 65 20 50 72 69 6e 74 65 72 20 53 74 61 6e 64 61 72 64 20 76 31 30 2e 37 2e 33 2e 34 30 31 } //2 PDF-XChange Printer Standard v10.7.3.401
		$a_81_1 = {6e 73 69 73 2e 73 66 2e 6e 65 74 2f 4e 53 49 53 5f 45 72 72 6f 72 } //2 nsis.sf.net/NSIS_Error
		$a_81_2 = {54 72 61 63 6b 65 72 20 53 6f 66 74 77 61 72 65 20 4c 74 64 2e } //2 Tracker Software Ltd.
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2) >=6
 
}
rule Trojan_Win32_Adload_EM_MTB_2{
	meta:
		description = "Trojan:Win32/Adload.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_81_0 = {50 44 46 2d 58 43 68 61 6e 67 65 20 50 72 69 6e 74 65 72 20 53 74 61 6e 64 61 72 64 20 76 31 30 2e 37 2e 36 2e 34 30 34 } //2 PDF-XChange Printer Standard v10.7.6.404
		$a_81_1 = {6e 73 69 73 2e 73 66 2e 6e 65 74 2f 4e 53 49 53 5f 45 72 72 6f 72 } //2 nsis.sf.net/NSIS_Error
		$a_81_2 = {54 72 61 63 6b 65 72 20 53 6f 66 74 77 61 72 65 20 4c 74 64 2e } //2 Tracker Software Ltd.
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2) >=6
 
}