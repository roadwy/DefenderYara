
rule Trojan_AndroidOS_OpFakeSms_A{
	meta:
		description = "Trojan:AndroidOS/OpFakeSms.A,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {73 65 6e 74 53 6d 73 43 6f 75 6e 74 } //1 sentSmsCount
		$a_01_1 = {75 70 64 61 74 65 72 33 2f 4f 70 65 72 61 55 70 64 61 74 65 72 41 63 74 69 76 69 74 79 } //1 updater3/OperaUpdaterActivity
		$a_01_2 = {53 6d 73 4f 70 65 72 61 74 6f 72 2e 6a 61 76 61 } //1 SmsOperator.java
		$a_01_3 = {45 78 63 65 70 74 69 6f 6e 20 21 21 21 21 21 21 21 21 21 21 21 21 21 21 21 21 21 } //1 Exception !!!!!!!!!!!!!!!!!
		$a_01_4 = {72 61 77 2f 73 6d 73 2e 78 6d 6c } //1 raw/sms.xml
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}
rule Trojan_AndroidOS_OpFakeSms_A_2{
	meta:
		description = "Trojan:AndroidOS/OpFakeSms.A,SIGNATURE_TYPE_DEXHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {1f 00 2b 00 [0-08] 6e 10 [0-0c] 0c 00 [0-08] 11 00 [0-08] 22 01 2c 00 [0-08] 70 10 [0-0c] 62 00 [0-0a] 12 00 [0-08] 6e 10 ?? ?? 04 00 [0-08] 0a 02 [0-08] 34 20 [0-0a] 6e 10 [0-0c] 0c 00 [0-08] 62 01 [0-0a] 6e 30 ?? ?? 41 00 [0-08] 28 [0-09] 22 02 23 00 [0-08] 6e 20 [0-0c] 0a 03 [0-08] 70 20 ?? ?? 32 00 [0-08] 62 03 [0-0a] 6e 20 [0-0c] 0c 03 [0-08] 38 03 [0-0a] 62 03 [0-0a] 6e 20 ?? ?? 23 00 [0-08] 0c 02 [0-08] 6e 20 [0-0c] d8 00 00 01 [0-08] 28 [0-09] 6e 20 ?? ?? 04 00 [0-08] 0a 02 [0-08] 6e 20 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}