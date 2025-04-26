
rule Trojan_Win32_KeyLogger_ASH_MTB{
	meta:
		description = "Trojan:Win32/KeyLogger.ASH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 08 00 00 "
		
	strings :
		$a_01_0 = {25 30 38 78 2e 65 78 65 } //2 %08x.exe
		$a_01_1 = {33 33 30 31 4b 69 72 61 } //2 3301Kira
		$a_01_2 = {44 43 5f 4d 55 54 45 58 2d 34 57 54 4c 34 5a 52 } //1 DC_MUTEX-4WTL4ZR
		$a_01_3 = {47 42 76 6f 4e 69 64 44 4d 4f 67 49 55 47 4a 31 75 76 5a 51 33 70 65 62 43 53 6a 43 77 4c 42 63 48 58 56 33 43 78 61 70 74 44 63 56 44 68 4c 38 53 77 6d 73 61 64 30 66 6b 4b 65 78 54 35 65 77 52 66 61 51 32 64 77 35 52 6f 34 63 4f 4c 57 63 5a 72 43 61 47 } //1 GBvoNidDMOgIUGJ1uvZQ3pebCSjCwLBcHXV3CxaptDcVDhL8Swmsad0fkKexT5ewRfaQ2dw5Ro4cOLWcZrCaG
		$a_01_4 = {4b 65 79 6c 6f 67 67 65 72 20 69 73 20 75 70 20 61 6e 64 20 72 75 6e 6e 69 6e 67 } //1 Keylogger is up and running
		$a_01_5 = {31 35 35 2e 31 35 2e 31 33 33 2e 36 39 } //1 155.15.133.69
		$a_01_6 = {31 39 37 2e 31 38 32 2e 31 38 36 2e 32 31 32 } //1 197.182.186.212
		$a_01_7 = {73 63 68 74 61 73 6b 73 20 2f 63 72 65 61 74 65 20 2f 74 6e 20 22 4d 79 54 61 73 6b 22 20 2f 74 72 20 22 25 73 22 20 2f 73 63 20 64 61 69 6c 79 20 2f 73 74 20 31 32 3a 30 30 } //1 schtasks /create /tn "MyTask" /tr "%s" /sc daily /st 12:00
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=5
 
}