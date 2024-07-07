
rule Trojan_Win32_Upatre_AMN_MTB{
	meta:
		description = "Trojan:Win32/Upatre.AMN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 04 00 00 "
		
	strings :
		$a_00_0 = {33 c0 39 44 24 0c 76 15 8b 4c 24 08 8a 0c 08 8b 54 24 04 88 0c 10 40 3b 44 24 0c 72 eb c2 0c 00 55 8b ec 81 ec 3c 08 00 00 } //10
		$a_80_1 = {53 68 65 6c 6c 45 78 65 63 75 74 65 57 } //ShellExecuteW  3
		$a_80_2 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 57 } //InternetOpenW  3
		$a_80_3 = {55 70 64 61 74 65 73 20 64 6f 77 6e 6c 6f 61 64 65 72 } //Updates downloader  3
	condition:
		((#a_00_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3) >=19
 
}