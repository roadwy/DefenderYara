
rule HackTool_Win32_Patcher_MTB{
	meta:
		description = "HackTool:Win32/Patcher!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {43 72 61 63 6b 65 72 20 4a 61 63 6b } //Cracker Jack  1
		$a_80_1 = {49 6e 6c 69 6e 65 20 70 61 74 63 68 } //Inline patch  1
		$a_80_2 = {50 61 74 63 68 74 61 72 67 65 74 } //Patchtarget  1
		$a_80_3 = {52 61 64 53 74 75 64 69 6f 20 58 45 37 20 50 61 74 63 68 20 } //RadStudio XE7 Patch   1
		$a_80_4 = {41 63 74 69 76 61 74 69 6f 6e 20 50 61 74 63 68 20 } //Activation Patch   1
		$a_80_5 = {66 69 6c 65 20 70 61 74 63 68 65 64 } //file patched  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=6
 
}
rule HackTool_Win32_Patcher_MTB_2{
	meta:
		description = "HackTool:Win32/Patcher!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {43 72 61 63 6b 69 6e 67 50 61 74 63 68 69 6e 67 } //CrackingPatching  1
		$a_80_1 = {49 44 4d 61 6e 2e 65 78 65 } //IDMan.exe  1
		$a_80_2 = {69 6e 73 74 61 6c 6c 20 49 44 4d 20 50 61 74 63 68 } //install IDM Patch  1
		$a_80_3 = {63 72 61 63 6b 69 6e 67 70 61 74 63 68 69 6e 67 2e 63 6f 6d } //crackingpatching.com  1
		$a_80_4 = {49 6e 74 65 72 6e 65 74 20 44 6f 77 6e 6c 6f 61 64 20 4d 61 6e 61 67 65 72 } //Internet Download Manager  1
		$a_80_5 = {63 6f 6d 62 6f 62 6f 78 } //combobox  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=6
 
}
rule HackTool_Win32_Patcher_MTB_3{
	meta:
		description = "HackTool:Win32/Patcher!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_80_0 = {44 6f 73 52 41 52 } //DosRAR  1
		$a_80_1 = {41 70 70 6c 79 20 72 65 67 69 73 74 72 61 74 69 6f 6e 2d 6e 61 6d 65 } //Apply registration-name  1
		$a_80_2 = {4c 69 71 36 39 65 72 73 } //Liq69ers  1
		$a_80_3 = {50 6f 6c 69 73 68 20 4d 65 64 69 63 61 6c 20 4d 61 69 6c 69 6e 67 20 53 70 2e 20 7a 20 6f 2e 6f 2e } //Polish Medical Mailing Sp. z o.o.  1
		$a_80_4 = {43 72 61 63 6b } //Crack  1
		$a_80_5 = {77 72 69 74 65 20 6f 66 20 69 6c 6c 65 67 61 6c 20 61 75 74 68 65 6e 74 69 63 79 20 69 6e 66 6f 72 6d 61 74 69 6f 6e } //write of illegal authenticy information  1
		$a_80_6 = {57 69 6e 52 41 52 20 43 72 61 63 6b 65 72 20 45 64 69 74 69 6f 6e 20 50 61 74 63 68 } //WinRAR Cracker Edition Patch  1
		$a_80_7 = {50 61 74 63 68 20 73 75 63 63 65 65 64 65 64 21 } //Patch succeeded!  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1) >=8
 
}