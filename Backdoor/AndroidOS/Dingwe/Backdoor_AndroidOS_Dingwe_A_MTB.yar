
rule Backdoor_AndroidOS_Dingwe_A_MTB{
	meta:
		description = "Backdoor:AndroidOS/Dingwe.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 6d 6e 74 2f 73 64 63 61 72 64 2f 44 6f 77 6e 6c 6f 61 64 2f 75 70 64 61 74 65 2e 61 70 6b } //01 00  /mnt/sdcard/Download/update.apk
		$a_00_1 = {2f 46 69 6c 65 73 65 6e 64 2f 75 70 6c 6f 61 64 5f 66 69 6c 65 } //01 00  /Filesend/upload_file
		$a_00_2 = {2f 43 6f 6d 6d 61 6e 64 73 2f 64 65 6c 65 74 65 5f 63 6f 6d 6d } //01 00  /Commands/delete_comm
		$a_00_3 = {63 6f 6d 2e 63 6f 6e 6e 65 63 74 } //01 00  com.connect
		$a_00_4 = {67 65 74 57 68 61 74 73 41 70 70 5f 6f 66 66 } //01 00  getWhatsApp_off
		$a_00_5 = {73 61 76 65 49 6e 63 6f 6d 69 6e 67 43 61 6c 6c } //01 00  saveIncomingCall
		$a_00_6 = {67 65 74 69 6e 62 6f 78 73 6d 73 } //00 00  getinboxsms
	condition:
		any of ($a_*)
 
}