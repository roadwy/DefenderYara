
rule Trojan_Win32_Cobaltstrike_DB_MTB{
	meta:
		description = "Trojan:Win32/Cobaltstrike.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_81_0 = {5c 2e 5c 70 69 70 65 5c 56 6d 77 61 72 65 2e 30 30 30 30 30 30 30 30 30 30 2e 30 30 30 32 } //01 00  \.\pipe\Vmware.0000000000.0002
		$a_81_1 = {31 32 37 2e 30 2e 30 2e 31 } //01 00  127.0.0.1
		$a_81_2 = {67 69 67 61 62 69 67 73 76 63 2e 64 6c 6c } //01 00  gigabigsvc.dll
		$a_81_3 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00  IsDebuggerPresent
		$a_81_4 = {53 65 72 76 69 63 65 4d 61 69 6e } //01 00  ServiceMain
		$a_81_5 = {53 65 74 45 6e 64 4f 66 46 69 6c 65 } //01 00  SetEndOfFile
		$a_81_6 = {43 72 65 61 74 65 50 69 70 65 } //01 00  CreatePipe
		$a_81_7 = {63 6d 64 2e 65 78 65 } //01 00  cmd.exe
		$a_81_8 = {26 20 65 78 69 74 } //00 00  & exit
	condition:
		any of ($a_*)
 
}