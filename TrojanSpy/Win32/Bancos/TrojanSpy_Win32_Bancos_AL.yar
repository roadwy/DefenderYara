
rule TrojanSpy_Win32_Bancos_AL{
	meta:
		description = "TrojanSpy:Win32/Bancos.AL,SIGNATURE_TYPE_PEHSTR_EXT,07 00 05 00 07 00 00 "
		
	strings :
		$a_80_0 = {66 74 70 2e 65 6e 69 67 6d 61 73 62 72 2e 63 6f 6d } //ftp.enigmasbr.com  1
		$a_80_1 = {68 74 74 70 3a 2f 2f 37 32 2e 32 39 2e 38 30 2e 31 31 33 2f 7e 6e 6f 73 73 61 63 61 69 2f } //http://72.29.80.113/~nossacai/  1
		$a_80_2 = {66 74 6c 2e 64 6c 6c } //ftl.dll  1
		$a_80_3 = {6f 6b 72 2e 64 6c 6c } //okr.dll  1
		$a_80_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //Software\Microsoft\Windows\CurrentVersion\Run  1
		$a_80_5 = {62 61 6e 6b 69 6e 67 } //banking  1
		$a_02_6 = {5c 00 75 00 70 00 77 00 69 00 6e 00 [0-06] 2e 00 74 00 78 00 74 00 } //1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_02_6  & 1)*1) >=5
 
}