
rule Trojan_Win32_Delf_NB_MTB{
	meta:
		description = "Trojan:Win32/Delf.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 03 00 "
		
	strings :
		$a_81_0 = {42 69 74 42 6c 74 } //03 00  BitBlt
		$a_81_1 = {44 72 61 67 4b 69 6e 64 } //03 00  DragKind
		$a_81_2 = {44 6f 63 6b 20 7a 6f 6e 65 20 68 61 73 20 6e 6f 20 63 6f 6e 74 72 6f 6c } //03 00  Dock zone has no control
		$a_81_3 = {44 6f 6e 20 48 4f 20 64 6f 6e 2e 68 40 66 72 65 65 2e 66 72 } //03 00  Don HO don.h@free.fr
		$a_81_4 = {4e 6f 74 65 70 61 64 2b 2b 2e 65 78 65 } //03 00  Notepad++.exe
		$a_81_5 = {43 6f 70 79 45 6e 68 4d 65 74 61 46 69 6c 65 41 } //00 00  CopyEnhMetaFileA
	condition:
		any of ($a_*)
 
}