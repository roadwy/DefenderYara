
rule Trojan_BAT_RenameFiles_AYB_MTB{
	meta:
		description = "Trojan:BAT/RenameFiles.AYB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {42 6c 6f 63 6b 57 69 6e 64 6f 77 73 44 65 66 65 6e 64 65 72 } //2 BlockWindowsDefender
		$a_01_1 = {53 70 61 6d 4e 6f 74 65 70 61 64 } //1 SpamNotepad
		$a_00_2 = {44 00 69 00 73 00 61 00 62 00 6c 00 65 00 41 00 6e 00 74 00 69 00 53 00 70 00 79 00 77 00 61 00 72 00 65 00 } //1 DisableAntiSpyware
		$a_00_3 = {44 00 69 00 73 00 61 00 62 00 6c 00 65 00 54 00 61 00 73 00 6b 00 4d 00 67 00 72 00 } //1 DisableTaskMgr
		$a_01_4 = {43 68 61 6e 67 65 46 69 6c 65 45 78 74 65 6e 73 69 6f 6e 73 } //1 ChangeFileExtensions
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}