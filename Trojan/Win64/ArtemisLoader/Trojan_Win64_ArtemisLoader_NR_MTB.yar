
rule Trojan_Win64_ArtemisLoader_NR_MTB{
	meta:
		description = "Trojan:Win64/ArtemisLoader.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {48 8b 44 24 10 8b 00 c1 e0 08 48 8b 4c 24 08 8b 09 0f af c8 8b c1 8b c0 48 8b 4c 24 18 8b 09 48 8b 54 24 08 8b 12 48 0f af ca 48 c1 e9 18 48 03 c1 89 04 24 8b 04 24 48 83 c4 28 } //2
		$a_01_1 = {53 00 65 00 49 00 6d 00 70 00 65 00 72 00 73 00 6f 00 6e 00 61 00 74 00 65 00 50 00 72 00 69 00 76 00 69 00 6c 00 65 00 67 00 65 00 } //1 SeImpersonatePrivilege
		$a_01_2 = {52 00 75 00 6e 00 61 00 73 00 } //1 Runas
		$a_01_3 = {52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 ReadProcessMemory
		$a_01_4 = {77 00 69 00 6e 00 6c 00 6f 00 67 00 6f 00 6e 00 2e 00 65 00 78 00 65 00 } //1 winlogon.exe
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}