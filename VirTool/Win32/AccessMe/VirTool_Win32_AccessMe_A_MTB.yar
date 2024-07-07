
rule VirTool_Win32_AccessMe_A_MTB{
	meta:
		description = "VirTool:Win32/AccessMe.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_02_0 = {ff d0 89 45 90 01 01 c7 04 24 e8 03 00 00 a1 90 01 03 00 ff d0 83 ec 04 a1 90 01 03 00 ff d0 90 00 } //2
		$a_02_1 = {8d 70 01 89 34 24 e8 90 01 02 00 00 89 43 fc 8b 4f fc 89 74 24 08 89 4c 24 04 89 04 24 e8 90 01 02 00 00 39 7d 94 75 ca 90 00 } //2
		$a_01_2 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 57 69 6e 64 6f 77 73 55 70 64 61 74 65 2e 6c 6f 67 } //2 C:\WINDOWS\WindowsUpdate.log
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}