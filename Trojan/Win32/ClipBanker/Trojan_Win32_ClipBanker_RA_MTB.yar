
rule Trojan_Win32_ClipBanker_RA_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_81_0 = {6d 61 72 69 65 5c 44 65 73 6b 74 6f 70 5c 63 6c 69 70 6d 6f 6e 69 74 6f 72 20 4b 45 54 48 41 53 20 46 49 4e 41 4c 20 45 56 45 52 59 54 48 49 4e 47 20 46 49 58 45 44 5c 63 6c 69 70 6d 6f 6e 69 74 6f 72 } //1 marie\Desktop\clipmonitor KETHAS FINAL EVERYTHING FIXED\clipmonitor
		$a_01_1 = {43 4c 49 50 42 4f 41 52 44 3a 20 27 27 20 76 73 2e 20 27 27 } //1 CLIPBOARD: '' vs. ''
	condition:
		((#a_81_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win32_ClipBanker_RA_MTB_2{
	meta:
		description = "Trojan:Win32/ClipBanker.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //1 SOFTWARE\Borland\Delphi\RTL
		$a_00_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 37 00 34 00 2e 00 63 00 7a 00 } //1 http://74.cz
		$a_01_2 = {47 65 74 54 65 78 74 45 78 74 65 6e 74 50 6f 69 6e 74 33 32 41 } //1 GetTextExtentPoint32A
		$a_01_3 = {53 68 65 6c 6c 45 78 65 63 75 74 65 45 78 41 } //1 ShellExecuteExA
		$a_01_4 = {53 48 47 65 74 50 61 74 68 46 72 6f 6d 49 44 4c 69 73 74 41 } //1 SHGetPathFromIDListA
		$a_01_5 = {28 53 68 6c 4f 62 6a } //1 (ShlObj
		$a_01_6 = {55 72 6c 4d 6f 6e } //1 UrlMon
		$a_01_7 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 4d 79 41 70 70 5c } //1 C:\ProgramData\MyApp\
		$a_00_8 = {49 00 74 00 27 00 73 00 20 00 6c 00 69 00 6b 00 65 00 20 00 73 00 74 00 72 00 61 00 70 00 70 00 69 00 6e 00 67 00 20 00 61 00 20 00 72 00 6f 00 63 00 6b 00 65 00 74 00 20 00 65 00 6e 00 67 00 69 00 6e 00 65 00 20 00 74 00 6f 00 20 00 61 00 20 00 6d 00 69 00 6e 00 69 00 76 00 61 00 6e 00 2e 00 } //1 It's like strapping a rocket engine to a minivan.
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_00_8  & 1)*1) >=9
 
}