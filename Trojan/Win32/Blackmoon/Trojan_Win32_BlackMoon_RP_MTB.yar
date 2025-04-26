
rule Trojan_Win32_BlackMoon_RP_MTB{
	meta:
		description = "Trojan:Win32/BlackMoon.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,2a 00 2a 00 06 00 00 "
		
	strings :
		$a_01_0 = {65 61 78 20 65 63 78 20 65 64 78 20 65 62 78 20 65 73 70 20 65 62 70 20 65 73 69 20 65 64 69 } //10 eax ecx edx ebx esp ebp esi edi
		$a_01_1 = {6e 65 77 20 73 75 70 65 72 68 6f 6f 6b } //10 new superhook
		$a_01_2 = {43 68 61 6e 67 65 57 69 6e 64 6f 77 4d 65 73 73 61 67 65 46 69 6c 74 65 72 45 78 } //1 ChangeWindowMessageFilterEx
		$a_01_3 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //1 CreateRemoteThread
		$a_01_4 = {5c 2b 5c 2d 5d 2b 29 7c 28 54 48 52 45 41 44 53 54 41 43 4b 29 28 5c 64 2a 29 } //10 \+\-]+)|(THREADSTACK)(\d*)
		$a_01_5 = {42 6c 61 63 6b 4d 6f 6f 6e 20 52 75 6e 54 69 6d 65 20 45 72 72 6f 72 3a } //10 BlackMoon RunTime Error:
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10) >=42
 
}