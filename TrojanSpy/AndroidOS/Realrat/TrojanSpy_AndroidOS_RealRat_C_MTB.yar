
rule TrojanSpy_AndroidOS_RealRat_C_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/RealRat.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_00_0 = {5f 63 6f 6d 61 6e 64 } //1 _comand
		$a_00_1 = {5f 63 61 6c 6c 6c 6f 67 } //1 _calllog
		$a_00_2 = {61 6c 6c 2d 73 6d 73 2e 74 78 74 } //1 all-sms.txt
		$a_00_3 = {63 6f 6e 74 61 63 74 2e 74 78 74 } //1 contact.txt
		$a_00_4 = {2f 70 61 6e 65 6c 2e 70 68 70 } //1 /panel.php
		$a_00_5 = {68 69 64 65 41 70 70 49 63 6f 6e } //1 hideAppIcon
		$a_00_6 = {69 72 2f 54 72 6f 6c 2f 66 75 5a 6f 6f 6c } //1 ir/Trol/fuZool
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=6
 
}