
rule Trojan_Win32_CryptInject_D_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {67 69 66 74 2e 7a 69 70 } //1 gift.zip
		$a_81_1 = {56 43 44 44 61 65 6d 6f 6e 2e 65 78 65 } //1 VCDDaemon.exe
		$a_81_2 = {4b 61 69 6b 69 55 70 64 61 74 65 } //1 KaikiUpdate
		$a_81_3 = {4c 32 64 70 5a 6e 51 79 4c 6e 70 70 63 41 } //1 L2dpZnQyLnppcA
		$a_81_4 = {4c 32 64 70 5a 6e 51 75 65 6d 6c 77 } //1 L2dpZnQuemlw
		$a_81_5 = {49 53 4d 79 4d 44 49 78 51 33 6c 69 5a 58 4a 49 4e 47 4e 4c 4d 33 4a 41 4a 51 } //1 ISMyMDIxQ3liZXJINGNLM3JAJQ
		$a_81_6 = {5a 58 68 6c 59 33 56 6a 59 57 38 75 63 47 68 77 } //1 ZXhlY3VjYW8ucGhw
		$a_81_7 = {64 33 64 33 4c 6e 4a 6c 63 33 52 68 64 58 4a 68 62 6e 52 6c 59 32 68 68 62 6d 64 68 65 53 35 6a 62 32 30 75 59 6e 49 } //1 d3d3LnJlc3RhdXJhbnRlY2hhbmdheS5jb20uYnI
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}