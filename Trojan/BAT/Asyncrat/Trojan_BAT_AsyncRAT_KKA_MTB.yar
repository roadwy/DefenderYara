
rule Trojan_BAT_AsyncRAT_KKA_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.KKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 06 00 00 "
		
	strings :
		$a_81_0 = {2f 43 20 41 54 54 52 49 42 20 2b 48 20 22 } //6 /C ATTRIB +H "
		$a_81_1 = {45 74 77 45 76 65 6e 74 57 72 69 74 65 } //5 EtwEventWrite
		$a_81_2 = {52 65 67 69 73 74 65 72 2d 53 63 68 65 64 75 6c 65 64 54 61 73 6b 20 2d 54 61 73 6b 4e 61 6d 65 20 27 52 75 6e 74 69 6d 65 42 72 6f 6b 65 72 5f 73 74 61 72 74 75 70 5f } //4 Register-ScheduledTask -TaskName 'RuntimeBroker_startup_
		$a_81_3 = {5f 73 74 72 27 20 2d 54 72 69 67 67 65 72 20 28 4e 65 77 2d 53 63 68 65 64 75 6c 65 64 54 61 73 6b 54 72 69 67 67 65 72 20 2d 41 74 4c 6f 67 6f 6e 29 20 2d 41 63 74 69 6f 6e 20 28 4e 65 77 2d 53 63 68 65 64 75 6c 65 64 54 61 73 6b 41 63 74 69 6f 6e 20 2d 45 78 65 63 75 74 65 20 27 } //3 _str' -Trigger (New-ScheduledTaskTrigger -AtLogon) -Action (New-ScheduledTaskAction -Execute '
		$a_81_4 = {27 29 20 2d 53 65 74 74 69 6e 67 73 20 28 4e 65 77 2d 53 63 68 65 64 75 6c 65 64 54 61 73 6b 53 65 74 74 69 6e 67 73 53 65 74 20 2d 41 6c 6c 6f 77 53 74 61 72 74 49 66 4f 6e 42 61 74 74 65 72 69 65 73 20 2d 48 69 64 64 65 6e 20 2d 45 78 65 63 75 74 69 6f 6e 54 69 6d 65 4c 69 6d 69 74 20 30 29 20 2d 52 75 6e 4c 65 76 65 6c 20 48 69 67 68 65 73 74 20 2d 46 6f 72 63 65 } //2 ') -Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -Hidden -ExecutionTimeLimit 0) -RunLevel Highest -Force
		$a_81_5 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 52 65 70 6c 61 63 65 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 2c 22 53 75 62 43 68 61 72 22 2c 22 22 29 29 2e 52 75 6e 20 22 22 22 } //1 CreateObject(Replace("WScript.Shell","SubChar","")).Run """
	condition:
		((#a_81_0  & 1)*6+(#a_81_1  & 1)*5+(#a_81_2  & 1)*4+(#a_81_3  & 1)*3+(#a_81_4  & 1)*2+(#a_81_5  & 1)*1) >=21
 
}