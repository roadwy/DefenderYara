
rule Trojan_Win32_LightNeuron_A{
	meta:
		description = "Trojan:Win32/LightNeuron.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 0c 00 00 "
		
	strings :
		$a_80_0 = {43 4f 4d 4d 41 4e 44 5f 52 45 50 4c 59 5f 41 54 54 41 43 48 5f 4e 41 4d 45 } //COMMAND_REPLY_ATTACH_NAME  1
		$a_80_1 = {43 4f 4d 4d 41 4e 44 5f 52 45 50 4c 59 5f 53 55 42 4a 45 43 54 } //COMMAND_REPLY_SUBJECT  1
		$a_80_2 = {43 4f 4e 46 49 47 5f 46 49 4c 45 5f 4e 41 4d 45 } //CONFIG_FILE_NAME  1
		$a_80_3 = {43 4f 4e 46 49 47 5f 55 50 44 41 54 45 5f 49 4e 54 45 52 56 41 4c } //CONFIG_UPDATE_INTERVAL  1
		$a_80_4 = {44 45 42 55 47 5f 4c 4f 47 5f 46 49 4c 45 5f 4e 41 4d 45 } //DEBUG_LOG_FILE_NAME  1
		$a_80_5 = {4c 49 4d 49 54 53 5f 4d 41 49 4c 53 5f 50 45 52 5f 53 45 43 4f 4e 44 5f 52 45 46 52 45 53 48 5f 49 4e 54 45 52 56 41 4c } //LIMITS_MAILS_PER_SECOND_REFRESH_INTERVAL  1
		$a_80_6 = {4c 49 4d 49 54 53 5f 4d 45 4d 4f 52 59 5f 4c 4f 41 44 5f 52 45 46 52 45 53 48 5f 49 4e 54 45 52 56 41 4c } //LIMITS_MEMORY_LOAD_REFRESH_INTERVAL  1
		$a_80_7 = {50 4f 53 54 46 49 58 5f 49 4e 43 4f 4d 49 4e 47 5f 50 41 54 48 } //POSTFIX_INCOMING_PATH  1
		$a_80_8 = {53 45 4e 44 5f 41 54 5f 4e 49 47 48 54 } //SEND_AT_NIGHT  1
		$a_80_9 = {53 45 4e 44 5f 4e 45 57 5f 4d 41 49 4c 5f 53 45 52 56 45 52 } //SEND_NEW_MAIL_SERVER  1
		$a_80_10 = {54 4d 50 5f 49 44 5f 50 41 54 48 } //TMP_ID_PATH  1
		$a_80_11 = {5a 49 50 5f 46 49 4c 45 5f 4e 41 4d 45 } //ZIP_FILE_NAME  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1+(#a_80_11  & 1)*1) >=7
 
}