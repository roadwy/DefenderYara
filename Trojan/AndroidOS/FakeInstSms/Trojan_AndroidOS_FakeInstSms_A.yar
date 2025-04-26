
rule Trojan_AndroidOS_FakeInstSms_A{
	meta:
		description = "Trojan:AndroidOS/FakeInstSms.A,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 04 00 08 00 00 "
		
	strings :
		$a_01_0 = {67 65 74 53 74 72 69 6e 67 46 72 6f 6d 52 61 77 46 69 6c 65 } //1 getStringFromRawFile
		$a_01_1 = {74 65 63 73 65 6e 64 74 65 78 74 } //1 tecsendtext
		$a_01_2 = {63 75 72 72 65 6e 74 63 6f 75 6e 74 72 79 } //1 currentcountry
		$a_01_3 = {61 6e 69 6d 61 74 69 6f 6e 72 6f 77 } //1 animationrow
		$a_01_4 = {6e 6f 74 74 72 65 62 } //1 nottreb
		$a_01_5 = {74 65 63 72 6f 6f 6c } //1 tecrool
		$a_01_6 = {53 4d 53 5f 44 45 4c 49 56 45 52 45 44 } //1 SMS_DELIVERED
		$a_01_7 = {21 21 21 53 74 61 72 74 20 53 65 72 76 69 63 65 21 21 21 } //1 !!!Start Service!!!
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=4
 
}