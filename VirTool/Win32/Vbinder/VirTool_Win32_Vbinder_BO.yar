
rule VirTool_Win32_Vbinder_BO{
	meta:
		description = "VirTool:Win32/Vbinder.BO,SIGNATURE_TYPE_PEHSTR,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {6d 00 64 00 42 00 69 00 6e 00 64 00 65 00 72 00 46 00 69 00 6e 00 61 00 6c 00 5c 00 6d 00 64 00 43 00 72 00 79 00 70 00 74 00 5c 00 76 00 62 00 53 00 74 00 75 00 62 00 5c 00 76 00 62 00 53 00 74 00 75 00 62 00 2e 00 76 00 62 00 70 00 } //01 00  mdBinderFinal\mdCrypt\vbStub\vbStub.vbp
		$a_01_1 = {43 00 72 00 79 00 70 00 74 00 65 00 72 00 20 00 62 00 79 00 20 00 64 00 72 00 69 00 7a 00 7a 00 6c 00 65 00 2e 00 2e 00 20 00 43 00 6f 00 64 00 65 00 72 00 20 00 66 00 72 00 6f 00 6d 00 20 00 68 00 61 00 63 00 6b 00 68 00 6f 00 75 00 6e 00 64 00 } //01 00  Crypter by drizzle.. Coder from hackhound
		$a_01_2 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //00 00  WriteProcessMemory
	condition:
		any of ($a_*)
 
}