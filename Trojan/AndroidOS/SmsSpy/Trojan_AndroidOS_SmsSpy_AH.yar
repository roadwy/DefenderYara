
rule Trojan_AndroidOS_SmsSpy_AH{
	meta:
		description = "Trojan:AndroidOS/SmsSpy.AH,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 65 63 6f 6e 64 70 61 67 65 6f 66 67 72 65 65 64 } //2 secondpageofgreed
		$a_01_1 = {63 68 65 63 6b 53 6d 73 50 65 72 6d 69 73 73 69 6f 6e 4f 6e 43 6c 69 63 6b } //2 checkSmsPermissionOnClick
		$a_01_2 = {64 65 65 70 38 34 4d 6f 62 30 32 31 69 6c 65 37 38 52 65 67 36 69 73 74 65 72 38 39 35 65 64 30 35 34 53 75 63 38 39 63 65 73 73 39 66 75 6c 6c 79 32 30 32 34 } //2 deep84Mob021ile78Reg6ister895ed054Suc89cess9fully2024
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=4
 
}