
rule Trojan_AndroidOS_Fakechatgpt_A{
	meta:
		description = "Trojan:AndroidOS/Fakechatgpt.A,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {61 6e 64 72 6f 69 64 2e 61 70 70 2e 61 63 74 69 6f 6e 2e 41 44 44 5f 44 45 56 49 43 45 5f 41 44 4d 49 4e } //1 android.app.action.ADD_DEVICE_ADMIN
		$a_01_1 = {2f 73 79 73 74 65 6d 2f 62 69 6e 2f 73 63 72 65 65 6e 63 61 70 20 2d 70 20 2f 73 64 63 61 72 64 2f 72 6f 6f 74 53 55 2e 70 6e 67 } //1 /system/bin/screencap -p /sdcard/rootSU.png
		$a_01_2 = {53 4d 53 5b } //1 SMS[
		$a_01_3 = {6f 6e 44 69 73 61 62 6c 65 52 65 71 75 65 73 74 65 64 } //1 onDisableRequested
		$a_01_4 = {2f 65 78 69 74 2f 63 68 61 74 } //1 /exit/chat
		$a_01_5 = {57 72 69 74 65 20 61 20 6d 65 73 73 61 67 65 } //1 Write a message
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}