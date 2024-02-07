
rule Backdoor_BAT_AsyncRAT_YA_MTB{
	meta:
		description = "Backdoor:BAT/AsyncRAT.YA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {67 00 65 00 74 00 44 00 72 00 69 00 76 00 65 00 72 00 73 00 } //01 00  getDrivers
		$a_01_1 = {73 00 6f 00 63 00 6b 00 65 00 74 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 } //01 00  socketDownload
		$a_01_2 = {73 00 65 00 6e 00 64 00 4d 00 65 00 6d 00 6f 00 72 00 79 00 } //01 00  sendMemory
		$a_01_3 = {75 00 73 00 62 00 53 00 70 00 72 00 65 00 61 00 64 00 } //01 00  usbSpread
		$a_01_4 = {72 00 65 00 6d 00 6f 00 74 00 65 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 } //01 00  remoteDesktop
		$a_01_5 = {62 00 6f 00 74 00 4b 00 69 00 6c 00 6c 00 65 00 72 00 } //01 00  botKiller
		$a_01_6 = {6b 00 65 00 79 00 4c 00 6f 00 67 00 67 00 65 00 72 00 } //01 00  keyLogger
		$a_01_7 = {75 00 70 00 6c 00 6f 00 61 00 64 00 46 00 69 00 6c 00 65 00 } //0a 00  uploadFile
		$a_01_8 = {2e 00 64 00 64 00 6e 00 73 00 2e 00 6e 00 65 00 } //0a 00  .ddns.ne
		$a_01_9 = {41 00 73 00 79 00 6e 00 63 00 52 00 41 00 54 00 } //00 00  AsyncRAT
	condition:
		any of ($a_*)
 
}