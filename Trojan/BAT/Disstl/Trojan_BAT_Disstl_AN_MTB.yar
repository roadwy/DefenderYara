
rule Trojan_BAT_Disstl_AN_MTB{
	meta:
		description = "Trojan:BAT/Disstl.AN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {73 00 69 00 72 00 5f 00 49 00 5f 00 61 00 6d 00 5f 00 69 00 6c 00 6c 00 75 00 73 00 69 00 6f 00 6e 00 69 00 6e 00 67 00 5f 00 6f 00 72 00 5f 00 79 00 6f 00 75 00 5f 00 72 00 65 00 61 00 64 00 69 00 6e 00 67 00 5f 00 6d 00 65 00 } //1 sir_I_am_illusioning_or_you_reading_me
		$a_01_1 = {65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 5f 00 6b 00 65 00 79 00 } //1 encrypted_key
		$a_01_2 = {53 00 6f 00 6d 00 65 00 20 00 72 00 65 00 74 00 61 00 72 00 64 00 20 00 77 00 68 00 6f 00 20 00 74 00 68 00 69 00 6e 00 6b 00 73 00 20 00 68 00 65 00 20 00 63 00 61 00 6e 00 20 00 72 00 65 00 76 00 65 00 72 00 73 00 65 00 20 00 74 00 68 00 69 00 73 00 20 00 61 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 } //1 Some retard who thinks he can reverse this application
		$a_01_3 = {53 00 65 00 6c 00 65 00 63 00 74 00 20 00 2a 00 20 00 66 00 72 00 6f 00 6d 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 43 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 53 00 79 00 73 00 74 00 65 00 6d 00 } //1 Select * from Win32_ComputerSystem
		$a_01_4 = {66 70 50 6b 31 31 53 64 72 44 65 63 72 79 70 74 } //1 fpPk11SdrDecrypt
		$a_01_5 = {65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 55 00 73 00 65 00 72 00 6e 00 61 00 6d 00 65 00 } //1 encryptedUsername
		$a_01_6 = {75 00 67 00 67 00 63 00 66 00 3a 00 2f 00 2f 00 6a 00 6a 00 6a 00 2e 00 71 00 65 00 62 00 63 00 6f 00 62 00 6b 00 2e 00 70 00 62 00 7a 00 2f 00 62 00 6e 00 68 00 67 00 75 00 32 00 2f 00 6e 00 68 00 67 00 75 00 62 00 65 00 76 00 6d 00 72 00 } //1 uggcf://jjj.qebcobk.pbz/bnhgu2/nhgubevmr
		$a_01_7 = {56 00 69 00 72 00 74 00 75 00 61 00 6c 00 42 00 6f 00 78 00 } //1 VirtualBox
		$a_01_8 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_01_9 = {56 00 4d 00 77 00 61 00 72 00 65 00 } //1 VMware
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}