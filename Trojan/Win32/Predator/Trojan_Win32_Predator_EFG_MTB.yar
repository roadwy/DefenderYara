
rule Trojan_Win32_Predator_EFG_MTB{
	meta:
		description = "Trojan:Win32/Predator.EFG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 15 00 08 00 00 "
		
	strings :
		$a_80_0 = {47 65 74 4c 6f 67 69 63 61 6c 44 72 69 76 65 53 74 72 69 6e 67 73 57 } //GetLogicalDriveStringsW  3
		$a_80_1 = {49 73 56 61 6c 69 64 4c 6f 63 61 6c 65 } //IsValidLocale  3
		$a_80_2 = {49 73 50 72 6f 63 65 73 73 6f 72 46 65 61 74 75 72 65 50 72 65 73 65 6e 74 } //IsProcessorFeaturePresent  3
		$a_80_3 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //IsDebuggerPresent  3
		$a_80_4 = {46 4d 65 73 73 61 67 65 4c 6f 6f 70 } //FMessageLoop  3
		$a_80_5 = {52 65 6e 45 78 69 74 49 6e 73 74 61 6e 63 65 } //RenExitInstance  3
		$a_80_6 = {52 65 6e 49 6e 69 74 49 6e 73 74 61 6e 63 65 } //RenInitInstance  3
		$a_80_7 = {46 6c 75 73 68 46 69 6c 65 42 75 66 66 65 72 73 } //FlushFileBuffers  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3+(#a_80_7  & 1)*3) >=21
 
}