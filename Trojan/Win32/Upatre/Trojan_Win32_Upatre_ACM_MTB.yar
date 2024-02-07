
rule Trojan_Win32_Upatre_ACM_MTB{
	meta:
		description = "Trojan:Win32/Upatre.ACM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 04 00 00 0a 00 "
		
	strings :
		$a_00_0 = {33 c0 39 44 24 0c 76 15 8b 4c 24 08 8a 0c 08 8b 54 24 04 88 0c 10 40 3b 44 24 0c 72 eb c2 0c 00 } //03 00 
		$a_81_1 = {55 70 64 61 74 65 73 20 64 6f 77 6e 6c 6f 61 64 65 72 } //03 00  Updates downloader
		$a_81_2 = {53 68 65 6c 6c 45 78 65 63 75 74 65 57 } //03 00  ShellExecuteW
		$a_81_3 = {2f 65 72 72 6f 72 2f 39 6d 6f 72 2e 65 78 65 } //00 00  /error/9mor.exe
	condition:
		any of ($a_*)
 
}