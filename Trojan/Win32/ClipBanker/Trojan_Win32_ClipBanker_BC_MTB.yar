
rule Trojan_Win32_ClipBanker_BC_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.BC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0a 00 00 02 00 "
		
	strings :
		$a_03_0 = {6a 3b c7 85 90 01 01 fd ff ff 00 00 00 00 8d 8d 90 01 01 fd ff ff 68 90 01 04 c7 85 90 01 01 fd ff ff 00 00 00 00 c7 85 90 01 01 fd ff ff 0f 00 00 00 c6 85 90 01 01 fd ff ff 00 e8 13 90 01 01 ff ff 68 90 01 04 c6 45 fc 90 01 01 0f 57 c0 8b 1d 90 00 } //02 00 
		$a_01_1 = {77 73 63 72 69 70 74 2e 65 78 65 20 2f 45 3a 6a 73 63 72 69 70 74 } //01 00  wscript.exe /E:jscript
		$a_01_2 = {52 65 67 4f 70 65 6e 4b 65 79 45 78 41 } //01 00  RegOpenKeyExA
		$a_01_3 = {52 65 67 53 65 74 56 61 6c 75 65 45 78 41 } //01 00  RegSetValueExA
		$a_01_4 = {52 65 67 43 6c 6f 73 65 4b 65 79 } //01 00  RegCloseKey
		$a_01_5 = {46 69 6e 64 52 65 73 6f 75 72 63 65 41 } //01 00  FindResourceA
		$a_01_6 = {4c 6f 61 64 52 65 73 6f 75 72 63 65 } //01 00  LoadResource
		$a_01_7 = {53 69 7a 65 6f 66 52 65 73 6f 75 72 63 65 } //01 00  SizeofResource
		$a_01_8 = {4c 6f 63 6b 52 65 73 6f 75 72 63 65 } //01 00  LockResource
		$a_01_9 = {57 69 6e 45 78 65 63 } //00 00  WinExec
	condition:
		any of ($a_*)
 
}