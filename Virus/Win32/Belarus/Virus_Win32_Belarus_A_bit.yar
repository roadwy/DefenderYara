
rule Virus_Win32_Belarus_A_bit{
	meta:
		description = "Virus:Win32/Belarus.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {42 45 4c 41 52 55 53 2d 56 49 52 55 53 2d 4d 41 4b 45 52 } //3 BELARUS-VIRUS-MAKER
		$a_01_1 = {45 78 70 6c 6f 72 65 72 2e 65 78 65 20 73 6d 72 73 73 2e 65 78 65 } //1 Explorer.exe smrss.exe
		$a_01_2 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 73 76 63 68 6f 73 74 2e 65 78 65 } //1 C:\WINDOWS\svchost.exe
		$a_01_3 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 66 72 65 69 7a 65 72 2e 65 78 65 } //1 C:\WINDOWS\system32\freizer.exe
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}