
rule Trojan_Win32_Delf_AOW{
	meta:
		description = "Trojan:Win32/Delf.AOW,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //5 SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {52 65 67 65 64 69 74 2e 65 78 65 20 2f 73 } //5 Regedit.exe /s
		$a_01_2 = {77 78 70 53 65 74 75 70 00 } //5
		$a_01_3 = {76 63 73 68 6f 77 2e 64 6c 6c } //5 vcshow.dll
		$a_01_4 = {77 77 77 31 2e 67 6f 61 64 73 2e 63 6e 2f 64 6f 77 6e 6c 6f 61 64 2f } //1 www1.goads.cn/download/
		$a_01_5 = {77 77 77 31 2e 73 6f 66 74 75 75 2e 63 6e 2f 64 6f 77 6e 6c 6f 61 64 2f } //1 www1.softuu.cn/download/
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=21
 
}