
rule Trojan_Win32_Tibs_DI{
	meta:
		description = "Trojan:Win32/Tibs.DI,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 08 00 00 "
		
	strings :
		$a_00_0 = {21 44 4f 53 20 69 73 20 64 65 61 64 } //1 !DOS is dead
		$a_00_1 = {61 76 7a 2e 65 78 65 3b } //1 avz.exe;
		$a_00_2 = {68 6c 65 67 65 68 72 69 76 69 68 62 75 67 50 68 53 65 44 65 } //2 hlegehrivihbugPhSeDe
		$a_00_3 = {4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e } //1 NT\CurrentVersion\Winlogon
		$a_01_4 = {45 58 50 4c 4f 44 45 20 30 } //1 EXPLODE 0
		$a_00_5 = {3f 77 69 6e 67 64 69 6e 67 73 } //1 ?wingdings
		$a_01_6 = {4f 52 45 52 74 26 } //1 ORERt&
		$a_01_7 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //1 CreateRemoteThread
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*2+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1+(#a_00_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=7
 
}