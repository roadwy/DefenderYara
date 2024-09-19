
rule Trojan_Win32_CobaltStrike_DB_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_81_0 = {5c 2e 5c 70 69 70 65 5c 56 6d 77 61 72 65 2e 30 30 30 30 30 30 30 30 30 30 2e 30 30 30 32 } //1 \.\pipe\Vmware.0000000000.0002
		$a_81_1 = {31 32 37 2e 30 2e 30 2e 31 } //1 127.0.0.1
		$a_81_2 = {67 69 67 61 62 69 67 73 76 63 2e 64 6c 6c } //1 gigabigsvc.dll
		$a_81_3 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
		$a_81_4 = {53 65 72 76 69 63 65 4d 61 69 6e } //1 ServiceMain
		$a_81_5 = {53 65 74 45 6e 64 4f 66 46 69 6c 65 } //1 SetEndOfFile
		$a_81_6 = {43 72 65 61 74 65 50 69 70 65 } //1 CreatePipe
		$a_81_7 = {63 6d 64 2e 65 78 65 } //1 cmd.exe
		$a_81_8 = {26 20 65 78 69 74 } //1 & exit
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=9
 
}