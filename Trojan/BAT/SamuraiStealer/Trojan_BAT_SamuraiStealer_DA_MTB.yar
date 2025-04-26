
rule Trojan_BAT_SamuraiStealer_DA_MTB{
	meta:
		description = "Trojan:BAT/SamuraiStealer.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1b 00 1b 00 08 00 00 "
		
	strings :
		$a_01_0 = {53 61 6d 75 72 61 69 2e 53 74 65 61 6c 65 72 } //20 Samurai.Stealer
		$a_01_1 = {67 65 74 5f 45 6e 63 72 79 70 74 65 64 55 73 65 72 6e 61 6d 65 } //1 get_EncryptedUsername
		$a_01_2 = {67 65 74 5f 43 6f 6d 70 75 74 65 72 4e 61 6d 65 } //1 get_ComputerName
		$a_01_3 = {67 65 74 5f 43 61 72 64 4e 75 6d 62 65 72 } //1 get_CardNumber
		$a_01_4 = {67 65 74 5f 50 61 73 73 77 6f 72 64 73 } //1 get_Passwords
		$a_01_5 = {67 65 74 5f 43 6f 6f 6b 69 65 73 } //1 get_Cookies
		$a_01_6 = {67 65 74 5f 41 75 74 6f 66 69 6c 6c 73 } //1 get_Autofills
		$a_01_7 = {67 65 74 5f 4c 6f 67 69 6e 73 } //1 get_Logins
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=27
 
}