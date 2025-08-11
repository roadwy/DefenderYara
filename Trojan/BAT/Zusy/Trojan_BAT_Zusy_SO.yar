
rule Trojan_BAT_Zusy_SO{
	meta:
		description = "Trojan:BAT/Zusy.SO,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {11 0b 11 08 11 08 11 08 5a d2 9c 11 08 17 58 13 08 11 08 11 0b 8e 69 fe 04 13 12 11 12 2d e1 } //2
		$a_81_1 = {41 6c 61 72 6d 50 6c 75 73 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //2 AlarmPlus.Properties.Resources.resources
		$a_81_2 = {24 30 61 34 39 36 38 66 34 2d 36 66 61 32 2d 34 33 62 32 2d 39 32 37 66 2d 34 62 33 61 63 61 30 35 65 62 33 31 } //2 $0a4968f4-6fa2-43b2-927f-4b3aca05eb31
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2) >=6
 
}