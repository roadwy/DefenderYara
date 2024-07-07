
rule Backdoor_iPhoneOS_EggShell_B_MTB{
	meta:
		description = "Backdoor:iPhoneOS/EggShell.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,0a 00 0a 00 07 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 73 79 73 73 65 72 76 65 72 } //2 com.sysserver
		$a_00_1 = {63 6f 6d 6d 61 6e 64 57 69 74 68 52 65 70 6c 79 3a 77 69 74 68 55 73 65 72 49 6e 66 6f 3a } //2 commandWithReply:withUserInfo:
		$a_00_2 = {63 6f 6d 6d 61 6e 64 57 69 74 68 4e 6f 52 65 70 6c 79 3a 77 69 74 68 55 73 65 72 49 6e 66 6f 3a } //2 commandWithNoReply:withUserInfo:
		$a_00_3 = {61 74 74 65 6d 70 74 55 6e 6c 6f 63 6b 57 69 74 68 50 61 73 73 63 6f 64 65 3a } //2 attemptUnlockWithPasscode:
		$a_01_4 = {6c 6f 63 61 74 69 6f 6e 6f 6e } //1 locationon
		$a_01_5 = {6c 61 73 74 61 70 70 } //1 lastapp
		$a_00_6 = {69 73 6d 75 74 65 64 } //1 ismuted
	condition:
		((#a_01_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_00_6  & 1)*1) >=10
 
}