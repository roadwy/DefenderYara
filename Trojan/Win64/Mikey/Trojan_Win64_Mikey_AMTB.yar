
rule Trojan_Win64_Mikey_AMTB{
	meta:
		description = "Trojan:Win64/Mikey!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_80_0 = {68 7a 6a 74 61 6a 6a 6b 6c 72 2e 62 61 74 } //hzjtajjklr.bat  2
		$a_80_1 = {5a 3a 5c 50 52 4f 4a 45 43 54 53 5c 57 69 6e 64 6f 77 73 43 6f 64 65 63 73 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 57 69 6e 64 6f 77 73 43 6f 64 65 63 73 2e 70 64 62 } //Z:\PROJECTS\WindowsCodecs\x64\Release\WindowsCodecs.pdb  2
		$a_80_2 = {55 6e 69 6e 73 74 2e 65 78 65 } //Uninst.exe  -100
		$a_80_3 = {55 6e 69 6e 73 74 61 6c 6c 65 72 2e 65 78 65 } //Uninstaller.exe  -100
		$a_80_4 = {55 6e 69 6e 73 74 61 6c 2e 65 78 65 } //Uninstal.exe  -100
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*-100+(#a_80_3  & 1)*-100+(#a_80_4  & 1)*-100) >=4
 
}