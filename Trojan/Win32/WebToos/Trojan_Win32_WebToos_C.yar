
rule Trojan_Win32_WebToos_C{
	meta:
		description = "Trojan:Win32/WebToos.C,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {57 65 62 54 6f 6f 73 00 } //1 敗呢潯s
		$a_01_1 = {44 49 53 50 49 44 5f 4e 45 57 57 49 4e 44 4f 57 32 3e 3e 3e 3e 3e 3e 3e 3e 3e 3e 3e 3e 3e 3e 3e 0a } //1
		$a_01_2 = {73 5f 73 76 6f 73 74 2e 69 6e 69 } //1 s_svost.ini
		$a_01_3 = {74 61 73 6b 68 30 73 74 2e 65 78 65 } //1 taskh0st.exe
		$a_03_4 = {c6 44 24 3c 05 6a 0c 68 ?? ?? ?? ?? 8d 4c 24 20 89 6c 24 38 89 5c 24 34 88 5c 24 24 e8 ?? ?? ?? ?? 8d 44 24 18 50 c6 44 24 40 06 e8 ?? ?? ?? ?? c6 44 24 3c 05 83 7c 24 30 10 72 0d 8b 4c 24 1c 51 e8 ?? ?? ?? ?? 83 c4 04 6a 0b 68 } //5
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*5) >=8
 
}