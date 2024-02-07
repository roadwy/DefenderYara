
rule TrojanSpy_AndroidOS_Monokle_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Monokle.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {6b 65 79 6c 6f 67 67 65 72 } //01 00  keylogger
		$a_00_1 = {64 69 73 61 62 6c 65 43 61 6d 65 72 61 53 6f 75 6e 64 } //01 00  disableCameraSound
		$a_00_2 = {2f 73 79 73 74 65 6d 2f 67 61 74 65 6b 65 65 70 65 72 2e 70 61 73 73 77 6f 72 64 2e 6b 65 79 } //01 00  /system/gatekeeper.password.key
		$a_00_3 = {2f 73 79 73 74 65 6d 2f 6d 65 64 69 61 2f 61 75 64 69 6f 2f 75 69 2f 56 69 64 65 6f 52 65 63 6f 72 64 2e 6f 67 } //01 00  /system/media/audio/ui/VideoRecord.og
		$a_00_4 = {41 75 64 69 6f 20 72 65 63 6f 72 64 20 53 4d 53 20 74 6f 20 66 69 6c 65 } //01 00  Audio record SMS to file
		$a_00_5 = {72 6d 20 2d 72 20 2f 73 79 73 74 65 6d 2f 61 70 70 2f 4d 6f 6e 69 74 6f 72 53 79 73 74 65 6d } //00 00  rm -r /system/app/MonitorSystem
	condition:
		any of ($a_*)
 
}