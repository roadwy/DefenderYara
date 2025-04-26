
rule Trojan_Win64_ZetaNile_O_dha{
	meta:
		description = "Trojan:Win64/ZetaNile.O!dha,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 50 61 63 6b 61 67 65 43 6f 6c 6f 72 5c 63 6f 6c 6f 72 63 70 6c 2e 65 78 65 20 30 43 45 31 32 34 31 41 34 34 35 35 37 41 41 34 33 38 46 32 37 42 43 36 44 34 41 43 41 32 34 36 } //1 C:\ProgramData\PackageColor\colorcpl.exe 0CE1241A44557AA438F27BC6D4ACA246
		$a_01_1 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 50 61 63 6b 61 67 65 43 6f 6c 6f 72 5c 63 6f 6c 6f 72 75 69 2e 64 6c 6c } //1 C:\ProgramData\PackageColor\colorui.dll
		$a_01_2 = {2f 54 4e 20 50 61 63 6b 61 67 65 43 6f 6c 6f 72 20 2f 46 } //1 /TN PackageColor /F
		$a_01_3 = {73 6f 66 74 77 61 72 65 5c 73 69 6d 6f 6e 74 61 74 68 61 6d 5c 70 75 74 74 79 } //1 software\simontatham\putty
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}