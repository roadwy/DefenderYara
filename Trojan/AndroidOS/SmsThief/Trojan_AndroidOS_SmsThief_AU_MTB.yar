
rule Trojan_AndroidOS_SmsThief_AU_MTB{
	meta:
		description = "Trojan:AndroidOS/SmsThief.AU!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 6d 73 4c 6f 67 67 65 72 } //1 SmsLogger
		$a_01_1 = {4c 4f 47 5f 43 45 4c 4c 5f 49 44 } //1 LOG_CELL_ID
		$a_01_2 = {63 6f 6d 2e 64 61 64 64 79 73 65 79 65 2e 62 61 63 6b 75 70 6d 65 2e 63 61 6c 6c } //1 com.daddyseye.backupme.call
		$a_01_3 = {64 65 2f 61 6e 64 72 6f 69 64 2f 6b 65 65 70 65 72 } //1 de/android/keeper
		$a_01_4 = {56 6f 69 63 65 4c 6f 67 67 65 72 } //1 VoiceLogger
		$a_01_5 = {4d 6d 73 4f 62 73 65 72 76 65 72 } //1 MmsObserver
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}