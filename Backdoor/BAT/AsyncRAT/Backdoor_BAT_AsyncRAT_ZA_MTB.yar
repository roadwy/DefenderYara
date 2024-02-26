
rule Backdoor_BAT_AsyncRAT_ZA_MTB{
	meta:
		description = "Backdoor:BAT/AsyncRAT.ZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 00 76 00 63 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 } //01 00  svchost.exe
		$a_00_1 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //01 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_81_2 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 5f 5f 49 6e 73 74 61 6e 63 65 4f 70 65 72 61 74 69 6f 6e 45 76 65 6e 74 } //01 00  SELECT * FROM __InstanceOperationEvent
		$a_81_3 = {41 63 74 69 76 65 50 72 6f 63 65 73 73 43 6f 75 6e 74 20 66 6f 72 20 6b 69 6c 6c 65 64 20 70 72 6f 63 65 73 73 } //01 00  ActiveProcessCount for killed process
		$a_00_4 = {63 00 72 00 79 00 70 00 74 00 65 00 72 00 63 00 6f 00 72 00 65 00 } //01 00  cryptercore
		$a_00_5 = {49 73 44 65 62 75 67 45 6e 61 62 6c 65 64 } //01 00  IsDebugEnabled
		$a_00_6 = {4d 69 63 72 6f 73 6f 66 74 2e 56 69 73 75 61 6c 42 61 73 69 63 2e 44 65 76 69 63 65 73 } //00 00  Microsoft.VisualBasic.Devices
	condition:
		any of ($a_*)
 
}