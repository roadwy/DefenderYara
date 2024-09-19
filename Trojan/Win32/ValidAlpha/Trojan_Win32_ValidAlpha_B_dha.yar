
rule Trojan_Win32_ValidAlpha_B_dha{
	meta:
		description = "Trojan:Win32/ValidAlpha.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,ffffff90 01 ffffff90 01 04 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 53 63 72 65 65 6e 4d 6f 6e 69 74 54 68 72 65 61 64 } //100 main.ScreenMonitThread
		$a_01_1 = {6d 61 69 6e 2e 43 6d 64 53 68 65 6c 6c } //100 main.CmdShell
		$a_01_2 = {6d 61 69 6e 2e 47 65 74 41 6c 6c 46 6f 6c 64 65 72 73 41 6e 64 46 69 6c 65 73 } //100 main.GetAllFoldersAndFiles
		$a_01_3 = {6d 61 69 6e 2e 53 65 6c 66 44 65 6c 65 74 65 } //100 main.SelfDelete
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*100+(#a_01_2  & 1)*100+(#a_01_3  & 1)*100) >=400
 
}