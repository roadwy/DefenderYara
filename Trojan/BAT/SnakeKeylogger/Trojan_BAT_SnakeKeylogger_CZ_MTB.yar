
rule Trojan_BAT_SnakeKeylogger_CZ_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.CZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 0c 00 00 "
		
	strings :
		$a_81_0 = {5c 53 6e 61 6b 65 4b 65 79 6c 6f 67 67 65 72 5c } //5 \SnakeKeylogger\
		$a_81_1 = {2d 20 53 6e 61 6b 65 20 54 72 61 63 6b 65 72 20 2d } //3 - Snake Tracker -
		$a_81_2 = {24 25 54 65 6c 65 67 72 61 6d 44 76 24 } //2 $%TelegramDv$
		$a_81_3 = {4b 65 79 4c 6f 67 67 65 72 45 76 65 6e 74 41 72 67 73 } //2 KeyLoggerEventArgs
		$a_81_4 = {5c 64 69 73 63 6f 72 64 5c 4c 6f 63 61 6c 20 53 74 6f 72 61 67 65 5c 6c 65 76 65 6c 64 62 5c } //2 \discord\Local Storage\leveldb\
		$a_81_5 = {77 6c 61 6e 20 73 68 6f 77 20 70 72 6f 66 69 6c 65 } //2 wlan show profile
		$a_81_6 = {5c 4b 69 6e 7a 61 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 20 44 61 74 61 } //1 \Kinza\User Data\Default\Login Data
		$a_81_7 = {5c 53 70 75 74 6e 69 6b 5c 53 70 75 74 6e 69 6b 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 20 44 61 74 61 } //1 \Sputnik\Sputnik\User Data\Default\Login Data
		$a_81_8 = {5c 42 6c 61 63 6b 48 61 77 6b 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 20 44 61 74 61 } //1 \BlackHawk\User Data\Default\Login Data
		$a_81_9 = {67 65 74 5f 65 6e 63 72 79 70 74 65 64 50 61 73 73 77 6f 72 64 } //1 get_encryptedPassword
		$a_81_10 = {67 65 74 5f 65 6e 63 72 79 70 74 65 64 55 73 65 72 6e 61 6d 65 } //1 get_encryptedUsername
		$a_81_11 = {67 65 74 5f 74 69 6d 65 50 61 73 73 77 6f 72 64 43 68 61 6e 67 65 64 } //1 get_timePasswordChanged
	condition:
		((#a_81_0  & 1)*5+(#a_81_1  & 1)*3+(#a_81_2  & 1)*2+(#a_81_3  & 1)*2+(#a_81_4  & 1)*2+(#a_81_5  & 1)*2+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1) >=20
 
}