
rule Backdoor_MacOS_Macma_A_MTB{
	meta:
		description = "Backdoor:MacOS/Macma.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 63 ca 48 89 8d 90 01 02 ff ff 48 8b 85 90 01 02 ff ff 48 8b 8d 90 01 02 ff ff ba 01 00 00 00 48 8b bd 90 01 02 ff ff 48 89 c6 e8 90 01 03 00 48 89 85 90 01 02 ff ff e9 00 00 00 00 48 8d 85 90 01 02 ff ff 48 89 85 90 01 02 ff ff 48 8d 05 90 01 02 04 00 48 89 85 90 01 02 ff ff 48 8b bd 90 01 02 ff ff 48 89 c6 e8 90 01 03 00 48 89 85 90 01 02 ff ff e9 00 00 00 00 90 00 } //2
		$a_00_1 = {2f 4c 69 62 72 61 72 79 2f 4c 61 75 6e 63 68 41 67 65 6e 74 73 2f 63 6f 6d 2e 55 73 65 72 41 67 65 6e 74 2e 76 61 2e 70 6c 69 73 74 } //1 /Library/LaunchAgents/com.UserAgent.va.plist
		$a_00_2 = {4d 75 74 65 78 3a 3a 7e 4d 75 74 65 78 28 29 20 70 74 68 72 65 61 64 5f 6d 75 74 65 78 5f 64 65 73 74 72 6f 79 20 65 72 72 6f 72 2c 63 6f 64 65 3d 25 64 } //1 Mutex::~Mutex() pthread_mutex_destroy error,code=%d
	condition:
		((#a_03_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=4
 
}