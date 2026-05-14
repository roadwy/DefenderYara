
rule Trojan_MacOS_MacSyncStealer_A_MTB{
	meta:
		description = "Trojan:MacOS/MacSyncStealer.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {74 74 70 73 3a 2f 2f 67 61 74 65 6d 61 64 65 6e 2e 73 70 61 63 65 2f 63 75 72 6c 2f } //1 ttps://gatemaden.space/curl/
		$a_01_1 = {2f 74 6d 70 2f 72 75 6e 6e 65 72 2e 63 6f 64 65 } //1 /tmp/runner.code
		$a_01_2 = {2f 4c 69 62 72 61 72 79 2f 4c 6f 67 73 2f 55 73 65 72 53 79 6e 63 57 6f 72 6b 65 72 2e 6c 6f 67 } //1 /Library/Logs/UserSyncWorker.log
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}