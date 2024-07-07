
rule Trojan_AndroidOS_SmsSpy_F_MTB{
	meta:
		description = "Trojan:AndroidOS/SmsSpy.F!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {2f 43 61 6d 65 72 61 2f 3f 65 3d 31 33 35 31 38 35 35 38 36 39 26 70 61 79 3d 70 61 73 61 72 67 61 64 } //1 /Camera/?e=1351855869&pay=pasargad
		$a_00_1 = {3a 2f 2f 75 61 69 6f 65 79 2e 67 61 2f 4d 61 69 6e 44 6f 6d 61 69 6e 2e 74 78 74 } //1 ://uaioey.ga/MainDomain.txt
		$a_00_2 = {64 6f 49 6e 42 61 63 6b 67 72 6f 75 6e 64 } //1 doInBackground
		$a_00_3 = {3a 2f 2f 75 61 69 6f 65 79 2e 67 61 2f 6f 74 70 2e 70 68 70 } //1 ://uaioey.ga/otp.php
		$a_00_4 = {69 72 2e 70 61 72 64 61 6b 68 74 2e 53 6d 73 } //1 ir.pardakht.Sms
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}
rule Trojan_AndroidOS_SmsSpy_F_MTB_2{
	meta:
		description = "Trojan:AndroidOS/SmsSpy.F!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 0b 00 00 "
		
	strings :
		$a_00_0 = {46 6c 61 73 7a 2e 6a 61 76 61 } //1 Flasz.java
		$a_00_1 = {46 69 6c 65 44 6f 77 6e 6c 6f 61 64 4c 69 73 74 65 6e 65 72 } //1 FileDownloadListener
		$a_00_2 = {3a 2f 2f 61 70 70 2e 7a 6a 68 79 74 2e 63 6f 6d 2f 6d 73 67 2f 7c 7c 6e 69 6d 73 69 3a 7c } //1 ://app.zjhyt.com/msg/||nimsi:|
		$a_00_3 = {3a 2f 2f 64 6f 77 6e 2e 72 68 6f 73 64 6e 2e 63 6f 6d 2f 33 36 30 2e 61 70 6b } //1 ://down.rhosdn.com/360.apk
		$a_00_4 = {53 45 4e 54 5f 53 4d 53 5f 41 43 54 49 4f 4e } //1 SENT_SMS_ACTION
		$a_00_5 = {3a 2f 2f 74 71 6b 6a 79 78 67 73 2e 63 6f 6d 3a 38 30 38 30 2f 6d 73 67 2f } //1 ://tqkjyxgs.com:8080/msg/
		$a_00_6 = {3a 2f 2f 69 70 2e 63 6e 6b 79 68 67 2e 63 6f 6d 2f 69 70 2e 70 68 70 } //1 ://ip.cnkyhg.com/ip.php
		$a_00_7 = {47 65 74 41 64 64 72 65 73 73 42 79 49 70 } //1 GetAddressByIp
		$a_00_8 = {63 68 65 63 6b 45 6d 61 69 6c 41 64 64 72 65 73 73 } //1 checkEmailAddress
		$a_00_9 = {63 68 65 63 6b 50 68 6f 6e 65 4e 75 6d } //1 checkPhoneNum
		$a_00_10 = {63 6f 6d 2e 73 78 77 7a 2e 6c 6f 76 65 74 68 65 61 74 65 72 2e 73 6d 73 2e 63 6f 6e 66 69 67 } //1 com.sxwz.lovetheater.sms.config
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1) >=7
 
}