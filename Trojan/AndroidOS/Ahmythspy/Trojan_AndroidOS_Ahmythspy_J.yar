
rule Trojan_AndroidOS_Ahmythspy_J{
	meta:
		description = "Trojan:AndroidOS/Ahmythspy.J,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {4c 61 68 6d 79 74 68 2f 6d 69 6e 65 2f 6b 69 6e 67 2f 61 68 6d 79 74 68 2f 6d 61 6e 61 67 65 72 73 2f 4c 6f 63 4d 61 6e 61 67 65 72 3b } //2 Lahmyth/mine/king/ahmyth/managers/LocManager;
		$a_00_1 = {78 30 30 30 30 63 6c } //2 x0000cl
		$a_00_2 = {44 69 73 61 62 6c 65 20 61 6c 6c 20 6e 6f 74 69 66 69 63 61 74 69 6f 6e 73 20 6f 66 20 74 68 69 73 20 61 70 70 2e } //2 Disable all notifications of this app.
		$a_00_3 = {4d 61 69 6e 41 63 74 69 76 69 74 79 24 24 45 78 74 65 72 6e 61 6c 53 79 6e 74 68 65 74 69 63 4c 61 6d 62 64 61 30 } //2 MainActivity$$ExternalSyntheticLambda0
	condition:
		((#a_01_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2) >=8
 
}