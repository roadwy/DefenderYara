
rule Trojan_Win32_GuLoader_QW_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.QW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_81_0 = {48 4f 4d 4f 43 48 52 4f 4d 49 43 } //3 HOMOCHROMIC
		$a_81_1 = {53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 } //3 Scripting.FileSystemObject
		$a_81_2 = {6b 69 6c 6f 77 61 74 74 65 6e 65 73 } //3 kilowattenes
		$a_81_3 = {77 69 6e 64 69 72 } //3 windir
		$a_81_4 = {5c 66 6c 4b 6b 6e 6b 55 52 36 42 33 4a 4d 50 51 6a 74 47 34 35 } //3 \flKknkUR6B3JMPQjtG45
		$a_81_5 = {46 6f 6c 64 65 72 45 78 69 73 74 73 } //3 FolderExists
		$a_81_6 = {46 65 61 74 68 65 72 74 6f 70 } //3 Feathertop
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3+(#a_81_6  & 1)*3) >=21
 
}