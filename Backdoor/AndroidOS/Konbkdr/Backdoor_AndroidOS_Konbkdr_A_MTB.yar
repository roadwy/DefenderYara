
rule Backdoor_AndroidOS_Konbkdr_A_MTB{
	meta:
		description = "Backdoor:AndroidOS/Konbkdr.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 09 00 00 "
		
	strings :
		$a_00_0 = {4c 61 70 70 2f 70 72 6f 6a 65 63 74 2f 61 70 70 63 68 65 63 6b 2f } //2 Lapp/project/appcheck/
		$a_00_1 = {75 70 2e 70 68 70 } //2 up.php
		$a_00_2 = {69 6e 73 74 61 6c 6c 5f 61 70 6b } //1 install_apk
		$a_00_3 = {67 65 74 5f 6b 65 79 6c 6f 67 } //1 get_keylog
		$a_00_4 = {6b 65 79 6c 6f 67 2e 74 78 74 } //1 keylog.txt
		$a_00_5 = {73 6d 73 5f 61 6c 6c 2e 74 78 74 } //1 sms_all.txt
		$a_00_6 = {70 68 6f 6e 65 63 61 6c 6c 2e 74 78 74 } //1 phonecall.txt
		$a_00_7 = {54 6f 74 61 6c 4d 73 67 2e 74 78 74 } //1 TotalMsg.txt
		$a_00_8 = {43 61 72 64 49 6e 66 6f 2e 74 78 74 } //1 CardInfo.txt
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1) >=6
 
}