
rule Ransom_MSIL_FileCoder_RHG_MTB{
	meta:
		description = "Ransom:MSIL/FileCoder.RHG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0b 00 00 "
		
	strings :
		$a_00_0 = {53 00 65 00 76 00 65 00 6e 00 52 00 65 00 63 00 6f 00 64 00 65 00 } //1 SevenRecode
		$a_00_1 = {2e 00 6d 00 73 00 68 00 31 00 78 00 6d 00 6c 00 } //1 .msh1xml
		$a_00_2 = {2e 00 73 00 68 00 74 00 6d 00 6c 00 } //1 .shtml
		$a_00_3 = {43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 50 00 75 00 62 00 6c 00 69 00 63 00 5c 00 44 00 6f 00 63 00 75 00 6d 00 65 00 6e 00 74 00 73 00 5c 00 } //1 C:\Users\Public\Documents\
		$a_00_4 = {44 00 69 00 73 00 61 00 62 00 6c 00 65 00 52 00 65 00 67 00 69 00 73 00 74 00 72 00 79 00 54 00 6f 00 6f 00 6c 00 73 00 } //1 DisableRegistryTools
		$a_00_5 = {44 00 69 00 73 00 61 00 62 00 6c 00 65 00 54 00 61 00 73 00 6b 00 4d 00 67 00 72 00 } //1 DisableTaskMgr
		$a_00_6 = {41 00 6e 00 64 00 79 00 4d 00 69 00 6c 00 6f 00 2e 00 6a 00 70 00 67 00 } //1 AndyMilo.jpg
		$a_00_7 = {57 00 61 00 6c 00 6c 00 70 00 61 00 70 00 65 00 72 00 } //1 Wallpaper
		$a_01_8 = {48 69 64 65 46 69 6c 65 73 } //1 HideFiles
		$a_01_9 = {45 6e 63 72 79 70 74 42 79 74 65 73 } //1 EncryptBytes
		$a_03_10 = {50 45 00 00 4c 01 03 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 01 30 } //2
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_03_10  & 1)*2) >=12
 
}