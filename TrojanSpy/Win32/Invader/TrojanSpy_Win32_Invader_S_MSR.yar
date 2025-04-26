
rule TrojanSpy_Win32_Invader_S_MSR{
	meta:
		description = "TrojanSpy:Win32/Invader.S!MSR,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {63 6f 64 69 6e 67 5c 70 72 6f 6a 65 63 74 5c 6d 61 69 6e 5c 72 65 73 75 6c 74 5c 72 65 73 75 6c 74 2e 70 64 62 } //1 coding\project\main\result\result.pdb
		$a_01_1 = {6e 74 6f 73 6b 72 6e 6c 2e 70 64 62 } //1 ntoskrnl.pdb
		$a_01_2 = {45 2e 4c 4f 56 44 4e 53 } //1 E.LOVDNS
		$a_01_3 = {63 00 20 00 73 00 74 00 61 00 72 00 74 00 } //1 c start
		$a_01_4 = {43 72 65 61 74 65 43 6c 69 65 6e 74 53 65 63 75 72 69 74 79 } //1 CreateClientSecurity
		$a_01_5 = {44 65 6c 65 74 65 41 63 63 65 73 73 } //1 DeleteAccess
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}