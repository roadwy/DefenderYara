
rule Trojan_Win64_Skeeyah_MG_MTB{
	meta:
		description = "Trojan:Win64/Skeeyah.MG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {33 c9 eb 38 48 63 05 ?? ?? ?? ?? 48 8d 0d ?? ?? ?? ?? 48 03 c1 81 38 50 45 } //1
		$a_00_1 = {43 3a 5c 72 65 5c 6a 64 6b 37 75 34 35 5c 32 32 39 5c 62 75 69 6c 64 5c 77 69 6e 64 6f 77 73 2d 61 6d 64 36 34 5c 74 6d 70 5c 73 75 6e 5c 6c 61 75 6e 63 68 65 72 5c 73 65 72 76 65 72 74 6f 6f 6c 5c 6f 62 6a 36 34 5c 73 65 72 76 65 72 74 6f 6f 6c 2e 70 64 62 } //1 C:\re\jdk7u45\229\build\windows-amd64\tmp\sun\launcher\servertool\obj64\servertool.pdb
		$a_00_2 = {31 00 2e 00 37 00 2e 00 30 00 5f 00 34 00 35 00 2d 00 62 00 31 00 38 00 } //1 1.7.0_45-b18
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
rule Trojan_Win64_Skeeyah_MG_MTB_2{
	meta:
		description = "Trojan:Win64/Skeeyah.MG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {33 c9 eb 38 48 63 05 ?? ?? ?? ?? 48 8d 0d ?? ?? ?? ?? 48 03 c1 81 38 50 45 } //1
		$a_00_1 = {43 3a 5c 72 65 5c 6a 64 6b 37 75 34 35 5c 32 32 39 5c 62 75 69 6c 64 5c 77 69 6e 64 6f 77 73 2d 61 6d 64 36 34 5c 74 6d 70 5c 73 75 6e 5c 6c 61 75 6e 63 68 65 72 5c 73 65 72 76 65 72 74 6f 6f 6c 5c 6f 62 6a 36 34 5c 73 65 72 76 65 72 74 6f 6f 6c 2e 70 64 62 } //1 C:\re\jdk7u45\229\build\windows-amd64\tmp\sun\launcher\servertool\obj64\servertool.pdb
		$a_00_2 = {31 00 2e 00 37 00 2e 00 30 00 5f 00 34 00 35 00 2d 00 62 00 31 00 38 00 } //1 1.7.0_45-b18
		$a_00_3 = {6a 6c 69 2e 64 6c 6c } //1 jli.dll
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}