
rule Trojan_AndroidOS_SmsSpy_A{
	meta:
		description = "Trojan:AndroidOS/SmsSpy.A,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {26 64 65 66 61 75 6c 74 5f 64 69 61 6c 65 72 5f 61 70 70 5f 6e 61 6d 65 3d } //2 &default_dialer_app_name=
		$a_00_1 = {26 64 65 66 61 75 6c 74 5f 64 69 61 6c 65 72 5f 70 61 63 6b 61 67 65 5f 6e 61 6d 65 3d } //2 &default_dialer_package_name=
		$a_01_2 = {2f 73 6f 75 6e 64 2f 53 6f 75 6e 64 53 65 72 76 69 63 65 } //2 /sound/SoundService
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}
rule Trojan_AndroidOS_SmsSpy_A_2{
	meta:
		description = "Trojan:AndroidOS/SmsSpy.A,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_00_0 = {4c 63 6f 6d 2f 70 73 69 70 68 6f 6e 33 2f 73 6d 73 72 65 63 65 69 76 65 64 } //2 Lcom/psiphon3/smsreceived
		$a_00_1 = {26 72 65 63 65 69 76 65 53 4d 53 3d 74 72 75 65 } //1 &receiveSMS=true
		$a_00_2 = {26 6c 61 73 74 73 6d 73 26 6d 65 73 73 61 67 65 3d } //1 &lastsms&message=
		$a_00_3 = {48 69 64 65 3d 54 72 75 65 26 61 6e 64 72 6f 69 64 69 64 3d } //1 Hide=True&androidid=
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=5
 
}
rule Trojan_AndroidOS_SmsSpy_A_3{
	meta:
		description = "Trojan:AndroidOS/SmsSpy.A,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_02_0 = {4c 63 6f 6d 2f 73 79 73 74 65 6d 2f 73 6d 73 2f [0-06] 2f 53 6d 53 73 65 72 76 65 72 } //3
		$a_02_1 = {4c 63 6f 6d 2f 73 79 73 74 65 6d 2f 73 6d 73 2f [0-06] 2f 53 6d 53 52 65 63 65 69 76 65 72 } //3
		$a_00_2 = {4c 63 6f 6d 2f 73 6d 73 2f 74 72 61 63 74 2f 53 6d 53 73 65 72 76 65 72 } //3 Lcom/sms/tract/SmSserver
		$a_00_3 = {4c 63 6f 6d 2f 73 6d 73 2f 74 72 61 63 74 2f 53 6d 53 52 65 63 65 69 76 65 72 } //3 Lcom/sms/tract/SmSReceiver
		$a_00_4 = {69 73 6c 6a } //1 islj
		$a_00_5 = {39 39 39 39 2d 30 31 2d 31 35 20 30 30 3a 35 30 3a 30 30 } //1 9999-01-15 00:50:00
	condition:
		((#a_02_0  & 1)*3+(#a_02_1  & 1)*3+(#a_00_2  & 1)*3+(#a_00_3  & 1)*3+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=7
 
}