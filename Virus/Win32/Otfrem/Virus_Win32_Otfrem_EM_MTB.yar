
rule Virus_Win32_Otfrem_EM_MTB{
	meta:
		description = "Virus:Win32/Otfrem.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {47 61 64 69 73 5f 4e 6f 79 61 } //1 Gadis_Noya
		$a_81_1 = {47 61 64 69 73 5f 41 5f 4e 6f 79 61 } //1 Gadis_A_Noya
		$a_81_2 = {50 6f 65 6e 79 61 20 4b 6f 65 5c 43 6f 70 79 20 46 69 6c 65 20 64 72 69 20 46 6c 61 73 68 5c 73 68 65 6c 6c 33 32 5c 50 72 6f 6a 53 68 65 6c 6c 33 32 2e 76 62 70 } //1 Poenya Koe\Copy File dri Flash\shell32\ProjShell32.vbp
		$a_81_3 = {48 65 79 20 74 68 69 73 20 69 73 20 61 20 73 61 6d 70 6c 65 } //1 Hey this is a sample
		$a_81_4 = {73 63 72 69 70 74 69 6e 67 2e 66 69 6c 65 73 79 73 74 65 6d 6f 62 6a 65 63 74 } //1 scripting.filesystemobject
		$a_81_5 = {67 65 74 73 70 65 63 69 61 6c 66 6f 6c 64 65 72 } //1 getspecialfolder
		$a_81_6 = {4f 54 69 66 56 54 61 21 58 6b 58 } //1 OTifVTa!XkX
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}