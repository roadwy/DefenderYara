
rule Trojan_AndroidOS_Spynote_B_MTB{
	meta:
		description = "Trojan:AndroidOS/Spynote.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,17 00 17 00 08 00 00 0a 00 "
		
	strings :
		$a_00_0 = {4c 79 70 73 2f 65 74 6f 6e 2f 61 70 70 6c 69 63 61 74 69 6f 6e 2f } //0a 00  Lyps/eton/application/
		$a_00_1 = {4c 74 6e 65 69 6c 63 2f 73 73 65 63 63 61 2f 65 74 6f 6d 65 72 2f 74 6e 65 69 6c 63 2f } //05 00  Ltneilc/ssecca/etomer/tneilc/
		$a_00_2 = {63 6f 6d 2e 78 78 78 2e 62 72 6f 61 64 63 61 73 74 2e 78 78 78 } //05 00  com.xxx.broadcast.xxx
		$a_00_3 = {2f 62 61 73 65 2e 61 70 6b } //01 00  /base.apk
		$a_00_4 = {6b 65 79 5f 6c 6f 67 67 65 72 5f 6f 6e 6c 69 6e 65 5f 73 74 61 72 74 } //01 00  key_logger_online_start
		$a_00_5 = {66 69 6c 65 5f 6d 61 6e 61 67 65 72 5f 77 72 69 74 65 5f 66 69 6c 65 } //01 00  file_manager_write_file
		$a_00_6 = {63 61 6d 65 72 61 5f 6d 61 6e 61 67 65 72 5f 63 61 70 74 75 72 65 } //01 00  camera_manager_capture
		$a_00_7 = {75 70 6c 6f 61 64 5f 66 69 6c 65 } //00 00  upload_file
		$a_00_8 = {5d 04 00 00 58 14 04 80 5c 2a 00 } //00 59 
	condition:
		any of ($a_*)
 
}