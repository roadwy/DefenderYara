
rule Trojan_AndroidOS_Ahmythspy_F{
	meta:
		description = "Trojan:AndroidOS/Ahmythspy.F,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 69 6d 2e 64 65 76 69 63 65 6c 6f 67 67 65 72 2e 6d 61 6e 61 67 65 72 73 2e 43 6f 6e 74 61 63 74 73 4d 61 6e 61 67 65 72 } //2 com.im.devicelogger.managers.ContactsManager
		$a_01_1 = {63 6f 6d 2f 65 74 65 63 68 64 2f 6c 33 6d 6f 6e 2f 46 69 6c 65 4d 61 6e 61 67 65 72 } //2 com/etechd/l3mon/FileManager
		$a_01_2 = {74 65 73 74 2f 67 6f 6f 67 6c 65 2f 63 6f 6d 2f 43 61 6c 6c 73 4d 61 6e 61 67 65 72 } //2 test/google/com/CallsManager
		$a_01_3 = {2f 43 61 6d 65 72 61 4d 61 6e 61 67 65 72 24 31 } //1 /CameraManager$1
		$a_01_4 = {63 6f 6e 74 61 63 74 73 4d 61 6e 61 67 65 72 43 6c 61 73 73 } //1 contactsManagerClass
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}