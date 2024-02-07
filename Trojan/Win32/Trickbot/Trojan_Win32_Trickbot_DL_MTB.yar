
rule Trojan_Win32_Trickbot_DL_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.DL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 03 00 "
		
	strings :
		$a_81_0 = {77 30 68 4c 63 57 58 4f 46 30 70 78 55 42 74 5a 74 4a 64 42 54 77 54 35 55 42 45 38 58 47 63 48 62 51 62 72 4f 42 } //03 00  w0hLcWXOF0pxUBtZtJdBTwT5UBE8XGcHbQbrOB
		$a_81_1 = {57 4d 7a 33 5a 79 4b 4a 73 36 59 66 41 49 79 76 53 64 63 5a 53 52 73 47 42 43 6b 71 4e 4f 6f 30 6b 41 65 63 } //01 00  WMz3ZyKJs6YfAIyvSdcZSRsGBCkqNOo0kAec
		$a_81_2 = {64 6c 6c 68 6f 73 74 2e 65 78 65 } //01 00  dllhost.exe
		$a_81_3 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //00 00  DllRegisterServer
	condition:
		any of ($a_*)
 
}