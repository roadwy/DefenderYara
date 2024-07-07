
rule Trojan_Win32_Emotet_PD_MSR{
	meta:
		description = "Trojan:Win32/Emotet.PD!MSR,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {25 00 41 00 54 00 54 00 41 00 43 00 4b 00 45 00 52 00 49 00 50 00 25 00 } //2 %ATTACKERIP%
		$a_01_1 = {67 65 74 5f 41 74 74 61 63 6b 65 72 49 70 } //2 get_AttackerIp
		$a_01_2 = {3c 41 74 74 61 63 6b 65 72 49 70 3e 6b 5f 5f 42 61 63 6b 69 6e 67 46 69 65 6c 64 } //2 <AttackerIp>k__BackingField
		$a_01_3 = {67 65 74 5f 43 75 72 72 65 6e 74 54 68 72 65 61 74 53 63 65 6e 61 72 69 6f } //1 get_CurrentThreatScenario
		$a_01_4 = {5f 6c 61 7a 79 46 69 6c 65 4c 6f 67 67 65 72 } //1 _lazyFileLogger
		$a_01_5 = {5f 6c 61 7a 79 52 65 6d 6f 74 65 4d 61 6e 61 67 65 6d 65 6e 74 43 6c 69 65 6e 74 } //1 _lazyRemoteManagementClient
		$a_01_6 = {67 65 74 5f 70 61 73 73 77 6f 72 64 } //1 get_password
		$a_01_7 = {67 65 74 5f 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 get_ProcessMemory
		$a_01_8 = {67 65 74 5f 6e 65 65 64 73 5f 72 65 6d 6f 74 65 5f 63 72 65 64 73 } //1 get_needs_remote_creds
		$a_01_9 = {67 65 74 5f 72 65 6d 6f 74 65 5f 6d 61 63 68 69 6e 65 5f 6c 6f 67 69 6e 73 } //1 get_remote_machine_logins
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}