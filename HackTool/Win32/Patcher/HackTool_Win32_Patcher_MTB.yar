
rule HackTool_Win32_Patcher_MTB{
	meta:
		description = "HackTool:Win32/Patcher!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_80_0 = {43 72 61 63 6b 65 72 20 4a 61 63 6b } //Cracker Jack  01 00 
		$a_80_1 = {49 6e 6c 69 6e 65 20 70 61 74 63 68 } //Inline patch  01 00 
		$a_80_2 = {50 61 74 63 68 74 61 72 67 65 74 } //Patchtarget  01 00 
		$a_80_3 = {52 61 64 53 74 75 64 69 6f 20 58 45 37 20 50 61 74 63 68 20 } //RadStudio XE7 Patch   01 00 
		$a_80_4 = {41 63 74 69 76 61 74 69 6f 6e 20 50 61 74 63 68 20 } //Activation Patch   01 00 
		$a_80_5 = {66 69 6c 65 20 70 61 74 63 68 65 64 } //file patched  00 00 
	condition:
		any of ($a_*)
 
}
rule HackTool_Win32_Patcher_MTB_2{
	meta:
		description = "HackTool:Win32/Patcher!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_80_0 = {43 72 61 63 6b 69 6e 67 50 61 74 63 68 69 6e 67 } //CrackingPatching  01 00 
		$a_80_1 = {49 44 4d 61 6e 2e 65 78 65 } //IDMan.exe  01 00 
		$a_80_2 = {69 6e 73 74 61 6c 6c 20 49 44 4d 20 50 61 74 63 68 } //install IDM Patch  01 00 
		$a_80_3 = {63 72 61 63 6b 69 6e 67 70 61 74 63 68 69 6e 67 2e 63 6f 6d } //crackingpatching.com  01 00 
		$a_80_4 = {49 6e 74 65 72 6e 65 74 20 44 6f 77 6e 6c 6f 61 64 20 4d 61 6e 61 67 65 72 } //Internet Download Manager  01 00 
		$a_80_5 = {63 6f 6d 62 6f 62 6f 78 } //combobox  00 00 
	condition:
		any of ($a_*)
 
}