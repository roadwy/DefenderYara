
rule Spammer_Win32_Darvec_A{
	meta:
		description = "Spammer:Win32/Darvec.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {69 70 3d 25 75 7c 75 3d 25 73 7c 70 3d 25 73 7c 4d 61 69 6c 46 72 6f 6d 3d 25 73 7c 46 72 6f 6d 3d 25 73 7c 6c 61 67 3d 25 73 } //01 00  ip=%u|u=%s|p=%s|MailFrom=%s|From=%s|lag=%s
		$a_01_1 = {4d 55 54 45 58 5f 4d 61 69 6c 5f 50 6c 75 67 69 6e 5f 76 } //01 00  MUTEX_Mail_Plugin_v
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 53 65 63 75 72 69 74 79 00 } //01 00  体呆䅗䕒卜捥牵瑩y
		$a_01_3 = {45 4e 00 00 43 4e 00 00 25 73 5c 25 73 00 00 00 63 6f 6e 66 69 67 2e 69 6e 69 } //00 00 
	condition:
		any of ($a_*)
 
}