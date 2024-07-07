
rule Trojan_Win32_Farfli_BX_MTB{
	meta:
		description = "Trojan:Win32/Farfli.BX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {73 5c 64 6c 6c 63 61 63 68 65 5c 73 65 74 68 63 2e 65 78 65 } //1 s\dllcache\sethc.exe
		$a_01_1 = {5b 45 78 65 63 75 74 65 5d } //1 [Execute]
		$a_01_2 = {73 5c 64 6c 6c 63 61 63 68 65 5c 6f 73 6b 2e 65 78 65 } //1 s\dllcache\osk.exe
		$a_01_3 = {73 5c 64 6c 6c 63 61 63 68 65 5c 6d 61 67 6e 69 66 79 2e 65 78 65 } //1 s\dllcache\magnify.exe
		$a_01_4 = {47 61 6d 65 20 4f 76 65 72 20 47 6f 6f 64 20 4c 75 63 6b 20 42 79 20 57 69 6e 64 } //1 Game Over Good Luck By Wind
		$a_01_5 = {53 79 73 74 65 6d 52 6f 6f 74 25 5c 73 79 73 74 65 6d 33 32 5c 74 65 72 6d 73 72 76 68 61 63 6b 2e 64 6c 6c } //1 SystemRoot%\system32\termsrvhack.dll
		$a_01_6 = {5b 53 6e 61 70 73 68 6f 74 5d } //1 [Snapshot]
		$a_01_7 = {5b 42 61 63 6b 73 70 61 63 65 5d } //1 [Backspace]
		$a_01_8 = {50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 52 75 25 64 2e 45 58 45 } //1 Program Files\Ru%d.EXE
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}