
rule Backdoor_AndroidOS_Ahmyth_A_MTB{
	meta:
		description = "Backdoor:AndroidOS/Ahmyth.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 09 00 00 "
		
	strings :
		$a_00_0 = {44 69 73 70 6c 61 79 20 70 6f 70 2d 75 70 20 77 69 6e 64 6f 77 73 20 77 68 69 6c 65 20 72 75 6e 6e 69 6e 67 20 69 6e 20 74 68 65 20 62 61 63 6b 67 72 6f 75 6e 64 } //2 Display pop-up windows while running in the background
		$a_00_1 = {53 63 72 65 65 6e 73 68 6f 74 } //1 Screenshot
		$a_00_2 = {73 65 6e 64 53 4d 53 } //1 sendSMS
		$a_00_3 = {3a 2f 2f 70 6f 6b 70 6f 6b 70 6f 6b 2d 36 33 35 37 33 2e 70 6f 72 74 6d 61 70 2e 68 6f 73 74 3a 36 33 35 37 33 3f 6d 6f 64 65 6c 3d } //1 ://pokpokpok-63573.portmap.host:63573?model=
		$a_00_4 = {63 6f 6e 74 65 6e 74 3a 2f 2f 63 61 6c 6c 5f 6c 6f 67 2f 63 61 6c 6c 73 } //1 content://call_log/calls
		$a_00_5 = {63 6f 6d 2f 70 72 6f 63 65 73 73 6f 72 2f 70 72 6f 2f 53 63 72 65 65 6e 52 65 63 6f 72 64 65 72 53 65 72 76 69 63 65 } //1 com/processor/pro/ScreenRecorderService
		$a_00_6 = {63 6f 6d 2e 70 72 6f 63 65 73 73 6f 72 2e 70 72 6f 2e 44 65 76 69 63 65 41 64 6d 69 6e } //1 com.processor.pro.DeviceAdmin
		$a_00_7 = {43 72 65 64 65 6e 74 69 61 6c 73 2e 6a 61 76 61 } //1 Credentials.java
		$a_02_8 = {43 6c 69 63 6b 20 27 50 65 72 6d 69 73 73 69 6f 6e 73 27 [0-03] 45 6e 61 62 6c 65 20 41 4c 4c 20 70 65 72 6d 69 73 73 69 6f 6e 73 } //1
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_02_8  & 1)*1) >=8
 
}