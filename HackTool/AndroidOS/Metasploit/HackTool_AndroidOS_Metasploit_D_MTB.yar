
rule HackTool_AndroidOS_Metasploit_D_MTB{
	meta:
		description = "HackTool:AndroidOS/Metasploit.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_00_0 = {2f 6d 65 74 61 73 70 6c 6f 69 74 2e 64 61 74 } //1 /metasploit.dat
		$a_00_1 = {6d 65 74 61 73 70 6c 6f 69 74 2f 50 61 79 6c 6f 61 64 54 72 75 73 74 4d 61 6e 61 67 65 72 2e 63 6c 61 73 73 } //1 metasploit/PayloadTrustManager.class
		$a_00_2 = {4c 63 6f 6d 2f 6d 65 74 61 73 70 6c 6f 69 74 2f 6d 65 74 65 72 70 72 65 74 65 72 2f 41 6e 64 72 6f 69 64 4d 65 74 65 72 70 72 65 74 65 72 } //1 Lcom/metasploit/meterpreter/AndroidMeterpreter
		$a_00_3 = {4c 6d 65 74 61 73 70 6c 6f 69 74 2f 4a 4d 58 50 61 79 6c 6f 61 64 } //1 Lmetasploit/JMXPayload
		$a_00_4 = {41 6e 64 72 6f 69 64 4d 65 74 65 72 70 72 65 74 65 72 } //1 AndroidMeterpreter
		$a_00_5 = {61 6e 64 72 6f 69 64 5f 64 75 6d 70 5f 63 61 6c 6c 6c 6f 67 } //1 android_dump_calllog
		$a_00_6 = {61 6e 64 72 6f 69 64 5f 64 75 6d 70 5f 63 6f 6e 74 61 63 74 73 } //1 android_dump_contacts
		$a_00_7 = {63 6c 69 70 62 6f 61 72 64 5f 6d 6f 6e 69 74 6f 72 5f 64 75 6d 70 } //1 clipboard_monitor_dump
		$a_00_8 = {73 74 64 61 70 69 5f 77 65 62 63 61 6d 5f 61 75 64 69 6f 5f 72 65 63 6f 72 64 5f 61 6e 64 72 6f 69 64 } //1 stdapi_webcam_audio_record_android
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1) >=9
 
}