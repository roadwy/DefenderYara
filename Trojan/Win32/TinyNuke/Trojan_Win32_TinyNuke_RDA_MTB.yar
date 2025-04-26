
rule Trojan_Win32_TinyNuke_RDA_MTB{
	meta:
		description = "Trojan:Win32/TinyNuke.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {48 49 44 44 45 4e 56 4e 43 } //1 HIDDENVNC
		$a_01_1 = {5c 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 73 68 65 6c 6c 33 32 2e 64 6c 6c 2c 23 36 31 } //1 \rundll32.exe shell32.dll,#61
		$a_01_2 = {54 61 73 6b 62 61 72 47 6c 6f 6d 4c 65 76 65 6c } //1 TaskbarGlomLevel
		$a_01_3 = {73 68 65 6c 6c 5f 54 72 61 79 57 6e 64 } //1 shell_TrayWnd
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}