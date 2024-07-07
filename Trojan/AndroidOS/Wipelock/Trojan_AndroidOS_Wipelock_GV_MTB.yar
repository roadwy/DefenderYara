
rule Trojan_AndroidOS_Wipelock_GV_MTB{
	meta:
		description = "Trojan:AndroidOS/Wipelock.GV!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {48 69 64 65 41 70 70 46 72 6f 6d 4c 61 75 6e 63 68 65 72 } //1 HideAppFromLauncher
		$a_01_1 = {77 69 70 65 4d 65 6d 6f 72 79 43 61 72 64 } //1 wipeMemoryCard
		$a_01_2 = {63 6f 6d 2f 65 6c 69 74 65 2f 4c 6f 63 6b 53 63 72 65 65 6e } //1 com/elite/LockScreen
		$a_01_3 = {69 73 43 61 6c 6c 66 72 6f 6d 50 61 73 73 77 6f 72 64 53 63 72 65 65 6e } //1 isCallfromPasswordScreen
		$a_01_4 = {63 6f 6e 74 65 6e 74 3a 2f 2f 73 6d 73 2f 69 6e 62 6f 78 } //1 content://sms/inbox
		$a_01_5 = {55 6e 69 6e 73 74 61 6c 6c 41 64 6d 69 6e 44 65 76 69 63 65 } //1 UninstallAdminDevice
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}