
rule TrojanDownloader_Win32_Dompiv_A{
	meta:
		description = "TrojanDownloader:Win32/Dompiv.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {65 63 68 6f 20 73 7c 20 63 61 63 6c 73 20 43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 67 62 70 4b 6d 2e 73 79 73 20 2f 44 20 54 4f 44 4f 53 } //1 echo s| cacls C:\WINDOWS\system32\drivers\gbpKm.sys /D TODOS
		$a_00_1 = {73 63 20 53 54 4f 50 20 47 62 70 4b 6d } //1 sc STOP GbpKm
		$a_00_2 = {73 63 20 44 45 4c 45 54 45 20 73 6e 6d 67 72 73 76 63 } //1 sc DELETE snmgrsvc
		$a_00_3 = {73 63 20 44 45 4c 45 54 45 20 73 6e 73 6d 73 } //1 sc DELETE snsms
		$a_02_4 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-20] 2f 00 7e 00 76 00 69 00 70 00 6d 00 6f 00 64 00 2f 00 70 00 75 00 62 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_02_4  & 1)*1) >=5
 
}