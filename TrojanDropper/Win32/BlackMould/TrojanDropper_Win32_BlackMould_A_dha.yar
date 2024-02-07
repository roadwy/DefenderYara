
rule TrojanDropper_Win32_BlackMould_A_dha{
	meta:
		description = "TrojanDropper:Win32/BlackMould.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 02 00 "
		
	strings :
		$a_01_0 = {25 77 69 6e 64 69 72 25 5c 73 79 73 74 65 6d 33 32 5c 69 6e 65 74 73 72 76 5c 73 72 76 68 74 74 70 2e 64 6c 6c } //02 00  %windir%\system32\inetsrv\srvhttp.dll
		$a_01_1 = {53 72 76 48 74 74 70 4d 6f 64 75 6c 65 } //01 00  SrvHttpModule
		$a_01_2 = {48 74 74 70 53 72 76 4d 6f 64 75 6c 65 } //02 00  HttpSrvModule
		$a_01_3 = {54 6f 20 63 6f 6e 66 69 67 75 72 65 20 41 70 70 6c 69 63 61 74 69 6f 6e 48 6f 73 74 2e 63 6f 6e 66 69 67 20 66 69 6c 65 20 4f 4b 2e 2e 2e } //01 00  To configure ApplicationHost.config file OK...
		$a_01_4 = {75 6e 73 74 61 6c 6c } //01 00  unstall
		$a_01_5 = {5b 45 52 52 4f 52 5d 3a 43 72 65 61 74 65 46 69 6c 65 20 74 6f 20 25 77 73 28 25 73 29 20 65 72 72 6f 72 2e 2e 2e } //01 00  [ERROR]:CreateFile to %ws(%s) error...
		$a_01_6 = {43 72 65 61 74 65 46 69 6c 65 20 25 77 73 28 25 73 29 20 4f 4b 2e 2e 2e } //00 00  CreateFile %ws(%s) OK...
	condition:
		any of ($a_*)
 
}