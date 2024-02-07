
rule Backdoor_Win32_Joanap_K_dha{
	meta:
		description = "Backdoor:Win32/Joanap.K!dha,SIGNATURE_TYPE_PEHSTR_EXT,28 00 28 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {6d 79 66 69 6c 65 } //0a 00  myfile
		$a_01_1 = {25 49 36 34 64 2e 72 73 74 } //0a 00  %I64d.rst
		$a_01_2 = {25 00 73 00 3f 00 61 00 63 00 74 00 69 00 6f 00 6e 00 3d 00 57 00 68 00 61 00 74 00 26 00 75 00 3d 00 25 00 49 00 36 00 34 00 75 00 } //0a 00  %s?action=What&u=%I64u
		$a_01_3 = {25 00 73 00 3f 00 61 00 63 00 74 00 69 00 6f 00 6e 00 3d 00 43 00 6d 00 64 00 52 00 65 00 73 00 26 00 75 00 3d 00 25 00 49 00 36 00 34 00 75 00 26 00 65 00 72 00 72 00 3d 00 65 00 78 00 65 00 63 00 2d 00 25 00 64 00 } //00 00  %s?action=CmdRes&u=%I64u&err=exec-%d
	condition:
		any of ($a_*)
 
}