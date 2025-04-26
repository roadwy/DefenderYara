
rule Trojan_Win32_Lokibot_PA_{
	meta:
		description = "Trojan:Win32/Lokibot.PA!!Lokibot.gen!SD,SIGNATURE_TYPE_ARHSTR_EXT,0a 00 0a 00 09 00 00 "
		
	strings :
		$a_81_0 = {2f 66 72 65 2e 70 68 70 } //3 /fre.php
		$a_81_1 = {25 73 5c 43 79 62 65 72 64 75 63 6b } //1 %s\Cyberduck
		$a_81_2 = {5c 51 75 70 5a 69 6c 6c 61 5c 70 72 6f 66 69 6c 65 73 5c 64 65 66 61 75 6c 74 5c 62 72 6f 77 73 65 64 61 74 61 2e 64 62 } //1 \QupZilla\profiles\default\browsedata.db
		$a_81_3 = {25 73 5c 25 73 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 20 44 61 74 61 } //1 %s\%s\User Data\Default\Login Data
		$a_81_4 = {53 45 4c 45 43 54 20 65 6e 63 72 79 70 74 65 64 55 73 65 72 6e 61 6d 65 2c 20 65 6e 63 72 79 70 74 65 64 50 61 73 73 77 6f 72 64 2c 20 66 6f 72 6d 53 75 62 6d 69 74 55 52 4c 2c 20 68 6f 73 74 6e 61 6d 65 20 46 52 4f 4d 20 6d 6f 7a 5f 6c 6f 67 69 6e 73 } //1 SELECT encryptedUsername, encryptedPassword, formSubmitURL, hostname FROM moz_logins
		$a_81_5 = {25 73 5c 54 68 75 6e 64 65 72 62 69 72 64 5c 70 72 6f 66 69 6c 65 73 2e 69 6e 69 } //1 %s\Thunderbird\profiles.ini
		$a_81_6 = {25 73 5c 46 6f 73 73 61 4d 61 69 6c 5c 70 72 6f 66 69 6c 65 73 2e 69 6e 69 } //1 %s\FossaMail\profiles.ini
		$a_81_7 = {25 73 5c 46 6f 78 6d 61 69 6c 5c 6d 61 69 6c } //1 %s\Foxmail\mail
		$a_81_8 = {25 73 5c 4e 45 54 47 41 54 45 5c 42 6c 61 63 6b 20 48 61 77 6b } //1 %s\NETGATE\Black Hawk
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=10
 
}