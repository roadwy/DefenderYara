
rule Backdoor_Win32_Rollingaim_A_dha{
	meta:
		description = "Backdoor:Win32/Rollingaim.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {4f 77 61 4d 6f 64 75 6c 65 } //01 00  OwaModule
		$a_01_1 = {67 65 74 5f 53 65 72 76 65 72 56 61 72 69 61 62 6c 65 73 } //01 00  get_ServerVariables
		$a_01_2 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  ToBase64String
		$a_01_3 = {67 65 74 5f 43 6f 6f 6b 69 65 73 } //01 00  get_Cookies
		$a_01_4 = {47 65 74 46 69 6c 65 73 } //01 00  GetFiles
		$a_01_5 = {73 65 74 5f 55 73 65 53 68 65 6c 6c 45 78 65 63 75 74 65 } //01 00  set_UseShellExecute
		$a_01_6 = {42 69 6e 61 72 79 57 72 69 74 65 } //01 00  BinaryWrite
		$a_01_7 = {4d 69 63 72 6f 73 6f 66 74 2e 45 78 63 68 61 6e 67 65 2e 43 6c 69 65 6e 74 73 2e 45 76 65 6e 74 2e 70 64 62 } //01 00  Microsoft.Exchange.Clients.Event.pdb
		$a_01_8 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 45 00 78 00 63 00 68 00 61 00 6e 00 67 00 65 00 2e 00 43 00 6c 00 69 00 65 00 6e 00 74 00 73 00 2e 00 45 00 76 00 65 00 6e 00 74 00 2e 00 64 00 6c 00 6c 00 } //01 00  Microsoft.Exchange.Clients.Event.dll
		$a_00_9 = {52 66 68 6e 20 4d 18 22 76 b5 33 11 12 33 0c 6d 0a 20 4d 18 22 9e a1 29 61 1c 76 b5 05 19 01 58 } //00 00 
	condition:
		any of ($a_*)
 
}