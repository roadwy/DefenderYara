
rule Trojan_Win32_Guloader_KW_MSR{
	meta:
		description = "Trojan:Win32/Guloader.KW!MSR,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {74 6f 72 76 65 74 73 20 73 65 70 75 6c 63 68 72 61 6c 69 73 65 73 } //1 torvets sepulchralises
		$a_81_1 = {74 65 72 6d 69 6e 61 6c 66 61 63 69 6c 69 74 65 74 } //1 terminalfacilitet
		$a_81_2 = {6b 69 74 74 65 6e 64 6f 6d 20 68 79 70 6f 70 68 6c 6f 65 6f 64 61 6c 2e 65 78 65 } //1 kittendom hypophloeodal.exe
		$a_81_3 = {64 6f 62 62 65 6c 74 65 72 6b 6c 72 69 6e 67 65 6e 73 } //1 dobbelterklringens
		$a_81_4 = {74 79 6b 6b 65 6c 73 65 72 6e 65 20 62 61 72 6b 69 6e 6a 69 } //1 tykkelserne barkinji
		$a_81_5 = {72 61 69 6c 77 61 79 20 67 69 6e 6f 72 69 74 65 20 74 75 6e 67 73 70 61 74 74 65 6e 73 } //1 railway ginorite tungspattens
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}