
rule HackTool_Win32_FindAVsignature_A{
	meta:
		description = "HackTool:Win32/FindAVsignature.A,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 05 00 00 0a 00 "
		
	strings :
		$a_80_0 = {46 69 6e 64 2d 41 56 53 69 67 6e 61 74 75 72 65 } //Find-AVSignature  fb ff 
		$a_01_1 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 64 00 6f 00 74 00 6e 00 65 00 74 00 63 00 6c 00 69 00 2e 00 62 00 6c 00 6f 00 62 00 2e 00 63 00 6f 00 72 00 65 00 2e 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 2e 00 6e 00 65 00 74 00 2f 00 } //fb ff  https://dotnetcli.blob.core.windows.net/
		$a_01_2 = {2d 00 54 00 65 00 6e 00 61 00 6e 00 74 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 } //fb ff  -TenantServicePassword
		$a_01_3 = {52 00 61 00 70 00 69 00 64 00 37 00 20 00 41 00 67 00 65 00 6e 00 74 00 } //f6 ff  Rapid7 Agent
		$a_01_4 = {5c 4d 53 54 49 43 57 65 66 44 65 74 65 63 74 69 6f 6e 73 5c 4c 69 62 5c 50 6f 77 65 72 73 68 65 6c 6c 50 61 72 73 65 72 5c 6f 62 6a 5c 61 6d 64 36 34 5c 50 6f 77 65 72 73 68 65 6c 6c 50 61 72 73 65 72 2e 70 64 62 } //00 00  \MSTICWefDetections\Lib\PowershellParser\obj\amd64\PowershellParser.pdb
		$a_00_5 = {5d 04 00 00 1b 0f 03 80 5c 2f } //00 00 
	condition:
		any of ($a_*)
 
}