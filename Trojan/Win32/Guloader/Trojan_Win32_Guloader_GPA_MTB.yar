
rule Trojan_Win32_Guloader_GPA_MTB{
	meta:
		description = "Trojan:Win32/Guloader.GPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {73 70 69 6c 6c 65 6e 65 73 20 63 65 72 61 6d 61 6c } //1 spillenes ceramal
		$a_81_1 = {61 61 72 73 74 69 64 65 72 73 20 75 74 6e 6b 65 6c 69 67 } //1 aarstiders utnkelig
		$a_81_2 = {76 6d 6d 65 6c 73 65 72 } //1 vmmelser
		$a_81_3 = {69 6e 6c 6f 6f 6b 69 6e 67 2e 65 78 65 } //1 inlooking.exe
		$a_81_4 = {72 65 6b 72 65 61 74 69 6f 6e 73 68 6a 65 6d 6d 65 6e 65 73 2e 43 68 6f } //1 rekreationshjemmenes.Cho
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}