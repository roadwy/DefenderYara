
rule Trojan_Win32_Fsysna_AS_MTB{
	meta:
		description = "Trojan:Win32/Fsysna.AS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 03 00 00 05 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //05 00  ShellExecuteA
		$a_01_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //05 00  URLDownloadToFileA
		$a_01_2 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 73 76 63 68 6f 73 74 2e 65 78 65 } //00 00  C:\ProgramData\svchost.exe
	condition:
		any of ($a_*)
 
}