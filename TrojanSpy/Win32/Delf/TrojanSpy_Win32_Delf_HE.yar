
rule TrojanSpy_Win32_Delf_HE{
	meta:
		description = "TrojanSpy:Win32/Delf.HE,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_00_0 = {44 65 6c 65 74 65 46 69 6c 65 44 6f 73 2e 62 61 74 } //1 DeleteFileDos.bat
		$a_00_1 = {26 6d 6f 6e 65 79 3d } //1 &money=
		$a_00_2 = {26 62 61 6e 6b 3d } //1 &bank=
		$a_02_3 = {57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c ?? ?? ?? 70 72 69 2e 64 6c 6c } //1
		$a_02_4 = {57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c ?? ?? ?? 69 6e 69 2e 64 6c 6c } //1
		$a_02_5 = {57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c ?? ?? ?? 74 6d 70 2e 64 6c 6c } //1
		$a_01_6 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //1 InternetOpenUrlA
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1+(#a_02_4  & 1)*1+(#a_02_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}