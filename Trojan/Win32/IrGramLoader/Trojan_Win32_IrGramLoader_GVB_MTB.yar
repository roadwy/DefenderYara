
rule Trojan_Win32_IrGramLoader_GVB_MTB{
	meta:
		description = "Trojan:Win32/IrGramLoader.GVB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {24 6d 44 69 72 20 3d 20 22 24 65 6e 76 3a 50 55 42 4c 49 43 5c } //1 $mDir = "$env:PUBLIC\
		$a_01_1 = {24 6d 4c 69 62 44 69 72 20 3d 20 28 24 6d 44 69 72 20 2b 20 27 4c 69 62 72 61 72 69 65 73 5c 27 29 3b } //1 $mLibDir = ($mDir + 'Libraries\');
		$a_01_2 = {4e 65 77 2d 49 74 65 6d 20 24 6d 4c 69 62 44 69 72 20 2d 49 74 65 6d 54 79 70 65 20 44 69 72 65 63 74 6f 72 79 20 2d 65 61 20 30 } //1 New-Item $mLibDir -ItemType Directory -ea 0
		$a_01_3 = {66 75 6e 63 74 69 6f 6e 20 43 68 65 63 6b } //1 function Check
		$a_01_4 = {57 48 49 4c 45 20 28 28 54 65 73 74 2d 50 61 74 68 20 28 22 24 65 6e 76 3a 54 45 4d 50 5c 69 6f 6e 63 68 65 63 6b 2e 6c 6f 67 22 29 29 20 2d 6e 65 20 24 74 72 75 65 29 } //1 WHILE ((Test-Path ("$env:TEMP\ioncheck.log")) -ne $true)
		$a_01_5 = {73 6c 65 65 70 20 35 } //1 sleep 5
		$a_01_6 = {64 65 6c 20 2d 66 6f 72 63 65 20 2d 65 61 20 30 } //1 del -force -ea 0
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}