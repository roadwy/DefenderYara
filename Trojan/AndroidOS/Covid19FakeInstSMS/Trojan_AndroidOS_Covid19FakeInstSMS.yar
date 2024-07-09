
rule Trojan_AndroidOS_Covid19FakeInstSMS{
	meta:
		description = "Trojan:AndroidOS/Covid19FakeInstSMS,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_00_0 = {74 69 6e 79 2e 63 63 2f 43 4f 56 49 44 2d 56 41 43 43 49 4e 45 } //2 tiny.cc/COVID-VACCINE
		$a_00_1 = {2f 63 68 61 70 6b 61 64 68 61 76 } //2 /chapkadhav
		$a_00_2 = {56 61 63 52 65 67 69 73 74 20 61 70 70 } //2 VacRegist app
		$a_01_3 = {4e 65 65 64 20 50 65 72 6d 69 73 73 69 6f 6e 20 74 6f 20 73 74 61 72 74 20 61 70 70 21 21 } //2 Need Permission to start app!!
		$a_00_4 = {63 6c 69 63 6b 20 6f 6e 20 61 64 20 61 6e 64 20 69 6e 73 74 61 6c 6c 20 61 70 70 20 74 6f 20 63 6f 6e 74 69 6e 75 65 21 21 } //2 click on ad and install app to continue!!
		$a_02_5 = {1a 01 0e 00 1a 02 0f 00 1a 03 10 00 1a 04 11 00 1a 05 12 00 1a 06 13 00 1a 07 14 00 1a 08 15 00 1a 09 16 00 1a 0a 17 00 1a 0b 18 00 1a 0c 19 00 1a 0d 1a 00 1a 0e 1b 00 1a 0f 1c 00 1a 10 1d 00 [0-52] 74 01 f5 01 1d 00 0c 02 22 03 6d 01 70 10 f7 01 03 00 1a 04 23 00 6e 20 f9 01 43 00 0c 03 46 04 00 01 } //3
		$a_00_6 = {61 48 52 30 63 44 6f 76 4c 33 52 70 62 6e 6b 75 59 32 4d 76 51 30 38 74 55 6b 56 48 53 51 } //3 aHR0cDovL3RpbnkuY2MvQ08tUkVHSQ
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_01_3  & 1)*2+(#a_00_4  & 1)*2+(#a_02_5  & 1)*3+(#a_00_6  & 1)*3) >=6
 
}