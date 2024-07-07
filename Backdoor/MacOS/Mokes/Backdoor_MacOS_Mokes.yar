
rule Backdoor_MacOS_Mokes{
	meta:
		description = "Backdoor:MacOS/Mokes,SIGNATURE_TYPE_MACHOHSTR_EXT,07 00 07 00 08 00 00 "
		
	strings :
		$a_00_0 = {73 75 62 5f 49 5f 62 6f 74 5f 6d 61 69 6e 5f 6d 61 63 78 5f 63 6c 61 6e 67 5f 72 65 6c 65 61 73 65 5f 70 6c 75 67 69 6e 5f 69 6d 70 6f 72 74 2e 63 70 70 } //1 sub_I_bot_main_macx_clang_release_plugin_import.cpp
		$a_00_1 = {73 75 62 5f 49 5f 71 72 63 5f 72 65 73 6f 75 72 63 65 5f 62 6f 74 2e 63 70 70 } //1 sub_I_qrc_resource_bot.cpp
		$a_00_2 = {73 75 62 5f 49 5f 61 76 66 63 61 6d 65 72 61 73 65 73 73 69 6f 6e 2e 6d 6d } //1 sub_I_avfcamerasession.mm
		$a_00_3 = {73 75 62 5f 49 5f 71 6d 65 64 69 61 6d 65 74 61 64 61 74 61 2e 63 70 70 } //1 sub_I_qmediametadata.cpp
		$a_00_4 = {73 75 62 5f 49 5f 71 61 75 64 69 6f 62 75 66 66 65 72 2e 63 70 70 } //1 sub_I_qaudiobuffer.cpp
		$a_00_5 = {73 75 62 5f 49 5f 71 61 75 64 69 6f 64 65 76 69 63 65 69 6e 66 6f 2e 63 70 70 } //1 sub_I_qaudiodeviceinfo.cpp
		$a_00_6 = {2f 63 63 58 58 58 58 58 58 } //1 /ccXXXXXX
		$a_00_7 = {6a 69 6b 65 6e 69 63 6b 31 32 61 6e 64 36 37 2e 63 6f 6d } //1 jikenick12and67.com
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=7
 
}