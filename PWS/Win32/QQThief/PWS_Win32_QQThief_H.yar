
rule PWS_Win32_QQThief_H{
	meta:
		description = "PWS:Win32/QQThief.H,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {25 73 5c 7e 40 55 77 4b 4a 2e 61 76 69 } //1 %s\~@UwKJ.avi
		$a_01_1 = {53 65 74 57 00 00 00 00 69 6e 64 6f 77 73 48 6f 00 00 00 00 6f 6b 45 78 57 } //1
		$a_01_2 = {5c 54 65 6e 63 65 6e 74 5c 51 51 5c 55 73 65 72 44 61 74 61 49 6e 66 6f 2e 69 6e 69 } //1 \Tencent\QQ\UserDataInfo.ini
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}