
rule Ransom_Win32_Medusalocker_S_MSR{
	meta:
		description = "Ransom:Win32/Medusalocker.S!MSR,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {2e 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 } //1 .encrypted
		$a_01_1 = {43 00 6f 00 6e 00 73 00 65 00 6e 00 74 00 50 00 72 00 6f 00 6d 00 70 00 74 00 42 00 65 00 68 00 61 00 76 00 69 00 6f 00 72 00 41 00 64 00 6d 00 69 00 6e 00 } //1 ConsentPromptBehaviorAdmin
		$a_01_2 = {4c 00 4f 00 43 00 4b 00 45 00 52 00 } //1 LOCKER
		$a_01_3 = {72 00 65 00 63 00 6f 00 76 00 65 00 72 00 79 00 65 00 6e 00 61 00 62 00 6c 00 65 00 64 00 20 00 4e 00 6f 00 } //1 recoveryenabled No
		$a_01_4 = {53 00 6c 00 65 00 65 00 70 00 20 00 61 00 74 00 } //1 Sleep at
		$a_01_5 = {44 00 45 00 4c 00 45 00 54 00 45 00 20 00 53 00 59 00 53 00 54 00 45 00 4d 00 53 00 54 00 41 00 54 00 45 00 42 00 41 00 43 00 4b 00 55 00 50 00 } //1 DELETE SYSTEMSTATEBACKUP
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}