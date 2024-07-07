
rule Virus_Win32_Delf_M{
	meta:
		description = "Virus:Win32/Delf.M,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4a 40 48 49 4c } //1 J@HIL
		$a_01_1 = {4e 6f 72 74 6f 6e 20 41 6e 74 69 76 69 72 75 73 20 53 65 72 76 65 72 } //1 Norton Antivirus Server
		$a_01_2 = {48 69 6a 61 63 6b 54 68 69 73 2e 65 78 65 } //1 HijackThis.exe
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 4c 6f 63 61 6c 65 73 } //1 Software\Borland\Delphi\Locales
		$a_01_4 = {47 61 6d 65 48 6f 75 73 65 2e 65 78 65 } //1 GameHouse.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}