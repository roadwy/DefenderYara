
rule Trojan_BAT_Marsilia_AMAB_MTB{
	meta:
		description = "Trojan:BAT/Marsilia.AMAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_81_0 = {4d 61 69 6e 20 70 72 6f 63 65 73 73 2c 20 73 74 61 72 74 20 70 65 72 73 69 73 74 65 6e 63 65 20 70 72 6f 63 65 73 73 } //01 00  Main process, start persistence process
		$a_81_1 = {63 72 79 70 74 65 72 63 6f 72 65 31 } //01 00  cryptercore1
		$a_81_2 = {73 76 63 68 6f 73 74 2e 65 78 65 } //01 00  svchost.exe
		$a_81_3 = {57 72 69 74 69 6e 67 20 72 65 67 69 73 74 72 79 20 6b 65 79 } //01 00  Writing registry key
		$a_81_4 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_81_5 = {45 72 72 6f 72 20 63 68 65 63 6b 69 6e 67 20 41 63 74 69 76 65 50 72 6f 63 65 73 73 43 6f 75 6e 74 20 66 6f 72 20 6b 69 6c 6c 65 64 20 70 72 6f 63 65 73 73 3a } //01 00  Error checking ActiveProcessCount for killed process:
		$a_81_6 = {41 6c 72 65 61 64 79 20 68 61 76 65 20 61 6e 20 65 78 69 73 74 69 6e 67 20 70 72 6f 63 65 73 73 2c 20 64 6f 6e 74 20 73 74 61 72 74 20 70 72 6f 63 65 73 73 2c 20 63 6f 75 6e 74 3a } //01 00  Already have an existing process, dont start process, count:
		$a_81_7 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 5f 5f 49 6e 73 74 61 6e 63 65 4f 70 65 72 61 74 69 6f 6e 45 76 65 6e 74 20 57 49 54 48 49 4e 20 20 31 20 57 48 45 52 45 20 54 61 72 67 65 74 49 6e 73 74 61 6e 63 65 } //01 00  SELECT * FROM __InstanceOperationEvent WITHIN  1 WHERE TargetInstance
		$a_81_8 = {66 69 6c 65 2e 65 78 65 } //00 00  file.exe
	condition:
		any of ($a_*)
 
}