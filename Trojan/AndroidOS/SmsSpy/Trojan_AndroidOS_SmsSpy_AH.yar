
rule Trojan_AndroidOS_SmsSpy_AH{
	meta:
		description = "Trojan:AndroidOS/SmsSpy.AH,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 08 00 00 "
		
	strings :
		$a_01_0 = {73 65 63 6f 6e 64 70 61 67 65 6f 66 67 72 65 65 64 } //2 secondpageofgreed
		$a_01_1 = {63 68 65 63 6b 53 6d 73 50 65 72 6d 69 73 73 69 6f 6e 4f 6e 43 6c 69 63 6b } //2 checkSmsPermissionOnClick
		$a_01_2 = {64 65 65 70 38 34 4d 6f 62 30 32 31 69 6c 65 37 38 52 65 67 36 69 73 74 65 72 38 39 35 65 64 30 35 34 53 75 63 38 39 63 65 73 73 39 66 75 6c 6c 79 32 30 32 34 } //2 deep84Mob021ile78Reg6ister895ed054Suc89cess9fully2024
		$a_01_3 = {61 63 74 69 6f 6e 3d 61 6e 64 72 6f 69 64 26 73 69 74 65 3d 25 73 26 73 65 6e 64 65 72 3d 25 73 26 6d 65 73 73 61 67 65 3d 25 73 } //2 action=android&site=%s&sender=%s&message=%s
		$a_01_4 = {72 6f 79 61 6c 2f 64 65 76 65 6c 6f 70 65 72 2f 6d 79 61 70 70 6c 69 63 61 74 69 6f 71 } //2 royal/developer/myapplicatioq
		$a_01_5 = {6d 79 61 70 70 6c 69 63 61 74 69 6f 6f 2f 52 65 63 65 69 76 65 53 4d 53 } //2 myapplicatioo/ReceiveSMS
		$a_01_6 = {52 65 63 65 69 76 65 53 4d 53 24 24 45 78 74 65 72 6e 61 6c 53 79 6e 74 68 65 74 69 63 41 70 69 4d 6f 64 65 6c 4f 75 74 6c 69 6e 65 30 } //2 ReceiveSMS$$ExternalSyntheticApiModelOutline0
		$a_01_7 = {61 70 6b 2d 73 6d 73 2d 61 72 67 75 6d 65 6e 74 73 30 31 } //2 apk-sms-arguments01
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2) >=4
 
}