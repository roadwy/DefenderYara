
rule Backdoor_AndroidOS_Kresoc_T_MTB{
	meta:
		description = "Backdoor:AndroidOS/Kresoc.T!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 07 00 00 01 00 "
		
	strings :
		$a_02_0 = {4c 63 6f 6d 2f 90 02 04 2f 70 6d 6f 6e 64 2f 72 65 66 2f 63 6f 6d 6d 61 6e 64 2f 52 65 6d 6f 74 65 53 65 74 4b 65 79 4c 6f 67 67 65 72 45 6e 61 62 6c 65 90 00 } //01 00 
		$a_02_1 = {4c 63 6f 6d 2f 90 02 06 2f 72 65 6d 6f 74 65 63 6f 6e 74 72 6f 6c 2f 52 65 6d 6f 74 65 46 75 6e 63 74 69 6f 6e 90 00 } //01 00 
		$a_00_2 = {50 72 6f 45 6e 61 62 6c 65 53 70 79 43 61 6c 6c 57 69 74 68 4d 6f 6e 69 74 6f 72 } //01 00  ProEnableSpyCallWithMonitor
		$a_00_3 = {63 68 6d 6f 64 20 37 35 35 20 2f 73 79 73 74 65 6d 2f 62 69 6e 2f 61 70 70 5f 70 72 6f 63 65 73 73 } //01 00  chmod 755 /system/bin/app_process
		$a_00_4 = {50 61 73 73 77 6f 72 64 43 61 70 74 75 72 65 4d 61 6e 61 67 65 72 } //01 00  PasswordCaptureManager
		$a_00_5 = {52 65 6d 6f 74 65 43 61 6d 65 72 61 41 63 74 69 76 69 74 79 } //01 00  RemoteCameraActivity
		$a_00_6 = {43 61 6c 6c 4c 6f 67 43 61 70 74 75 72 65 } //00 00  CallLogCapture
	condition:
		any of ($a_*)
 
}