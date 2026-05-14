
rule Trojan_BAT_LockScreen_MK_MTB{
	meta:
		description = "Trojan:BAT/LockScreen.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,4b 00 4b 00 05 00 00 "
		
	strings :
		$a_03_0 = {08 07 28 86 00 00 0a 73 28 00 00 0a 25 72 ?? 0f 00 70 6f 2e 00 00 0a 25 72 ?? 0f 00 70 08 72 ?? 00 00 70 28 2f 00 00 0a 6f 30 00 00 0a 25 17 6f 2b 00 00 0a 25 17 6f 2c 00 00 0a 25 16 6f 29 00 00 0a 25 17 6f 2a 00 00 0a 25 72 } //25
		$a_81_1 = {44 65 66 65 6e 64 65 72 45 78 63 6c 75 73 69 6f 6e 5f 7b 30 7d 2e 70 73 31 } //20 DefenderExclusion_{0}.ps1
		$a_81_2 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //15 DisableTaskMgr
		$a_81_3 = {44 69 73 61 62 6c 65 52 65 67 69 73 74 72 79 54 6f 6f 6c 73 } //10 DisableRegistryTools
		$a_81_4 = {2f 63 20 73 63 68 74 61 73 6b 73 20 2f 63 72 65 61 74 65 20 2f 66 20 2f 73 63 20 6f 6e 6c 6f 67 6f 6e 20 2f 64 65 6c 61 79 20 30 30 30 30 3a 30 30 20 2f 74 6e 20 22 } //5 /c schtasks /create /f /sc onlogon /delay 0000:00 /tn "
	condition:
		((#a_03_0  & 1)*25+(#a_81_1  & 1)*20+(#a_81_2  & 1)*15+(#a_81_3  & 1)*10+(#a_81_4  & 1)*5) >=75
 
}