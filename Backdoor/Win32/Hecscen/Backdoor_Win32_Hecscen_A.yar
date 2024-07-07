
rule Backdoor_Win32_Hecscen_A{
	meta:
		description = "Backdoor:Win32/Hecscen.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_01_0 = {47 65 74 53 6e 69 66 66 65 72 } //1 GetSniffer
		$a_01_1 = {47 65 74 4d 61 69 6c 65 72 } //1 GetMailer
		$a_01_2 = {49 50 43 53 63 61 6e 20 43 6f 6d 70 6c 65 74 65 21 } //1 IPCScan Complete!
		$a_01_3 = {52 65 6d 6f 74 65 43 6d 64 20 69 73 20 45 72 72 6f 72 21 } //1 RemoteCmd is Error!
		$a_01_4 = {47 45 54 20 68 74 74 70 3a 2f 2f 25 73 3a 25 73 2f 6d 73 75 70 64 61 74 65 2e 65 78 65 } //1 GET http://%s:%s/msupdate.exe
		$a_01_5 = {41 63 63 65 70 74 2d 4c 61 6e 67 75 61 67 65 3a 20 7a 68 2d 63 6e } //1 Accept-Language: zh-cn
		$a_03_6 = {6a 06 6a 01 6a 02 ff 15 90 01 03 10 89 85 90 01 02 ff ff 83 bd 90 01 02 ff ff ff 75 05 e9 90 01 01 00 00 00 6a 04 8d 8d 90 01 02 ff ff 51 68 06 10 00 00 68 ff ff 00 00 90 00 } //4
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_03_6  & 1)*4) >=6
 
}