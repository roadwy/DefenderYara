
rule Backdoor_Win32_Kelihos_gen_A{
	meta:
		description = "Backdoor:Win32/Kelihos.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 08 00 00 "
		
	strings :
		$a_80_0 = {5b 50 52 4f 58 59 5f 53 4f 43 4b 45 54 5f 57 4f 52 4b 45 52 } //[PROXY_SOCKET_WORKER  5
		$a_80_1 = {5b 4e 45 54 5f 53 45 52 56 45 52 5f 57 4f 52 4b 45 52 } //[NET_SERVER_WORKER  5
		$a_80_2 = {63 72 75 73 68 5f 64 65 74 65 63 74 65 64 5f 68 6f 73 74 } //crush_detected_host  3
		$a_80_3 = {43 6f 6d 70 72 6f 6d 7a 65 64 20 52 45 47 20 6b 65 79 3a } //Compromzed REG key:  3
		$a_80_4 = {6d 5f 64 69 63 74 69 6f 61 6e 72 69 65 73 5f 63 6f 6e 66 69 67 73 5f 69 64 73 } //m_dictioanries_configs_ids  3
		$a_80_5 = {5c 77 63 78 5f 66 74 70 2e 69 6e 69 } //\wcx_ftp.ini  3
		$a_80_6 = {5c 53 61 76 65 64 44 69 61 6c 6f 67 48 69 73 74 6f 72 79 5c 46 54 50 48 6f 73 74 } //\SavedDialogHistory\FTPHost  3
		$a_80_7 = {65 6e 63 72 79 70 74 65 64 50 61 73 73 77 6f 72 64 20 46 52 4f 4d 20 6d 6f 7a 5f 6c 6f 67 69 6e 73 } //encryptedPassword FROM moz_logins  3
	condition:
		((#a_80_0  & 1)*5+(#a_80_1  & 1)*5+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3+(#a_80_7  & 1)*3) >=13
 
}
rule Backdoor_Win32_Kelihos_gen_A_2{
	meta:
		description = "Backdoor:Win32/Kelihos.gen!A!!Kelihos.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,0d 00 0d 00 08 00 00 "
		
	strings :
		$a_80_0 = {5b 50 52 4f 58 59 5f 53 4f 43 4b 45 54 5f 57 4f 52 4b 45 52 } //[PROXY_SOCKET_WORKER  5
		$a_80_1 = {5b 4e 45 54 5f 53 45 52 56 45 52 5f 57 4f 52 4b 45 52 } //[NET_SERVER_WORKER  5
		$a_80_2 = {63 72 75 73 68 5f 64 65 74 65 63 74 65 64 5f 68 6f 73 74 } //crush_detected_host  3
		$a_80_3 = {43 6f 6d 70 72 6f 6d 7a 65 64 20 52 45 47 20 6b 65 79 3a } //Compromzed REG key:  3
		$a_80_4 = {6d 5f 64 69 63 74 69 6f 61 6e 72 69 65 73 5f 63 6f 6e 66 69 67 73 5f 69 64 73 } //m_dictioanries_configs_ids  3
		$a_80_5 = {5c 77 63 78 5f 66 74 70 2e 69 6e 69 } //\wcx_ftp.ini  3
		$a_80_6 = {5c 53 61 76 65 64 44 69 61 6c 6f 67 48 69 73 74 6f 72 79 5c 46 54 50 48 6f 73 74 } //\SavedDialogHistory\FTPHost  3
		$a_80_7 = {65 6e 63 72 79 70 74 65 64 50 61 73 73 77 6f 72 64 20 46 52 4f 4d 20 6d 6f 7a 5f 6c 6f 67 69 6e 73 } //encryptedPassword FROM moz_logins  3
	condition:
		((#a_80_0  & 1)*5+(#a_80_1  & 1)*5+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3+(#a_80_7  & 1)*3) >=13
 
}