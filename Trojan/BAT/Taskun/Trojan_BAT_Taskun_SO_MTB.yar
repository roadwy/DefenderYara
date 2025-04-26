
rule Trojan_BAT_Taskun_SO_MTB{
	meta:
		description = "Trojan:BAT/Taskun.SO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {5f 95 d2 13 10 11 0e 11 10 61 13 11 11 07 11 08 d4 11 11 } //2
		$a_01_1 = {4c 69 62 72 61 72 79 2e 4c 69 62 72 61 72 79 46 6f 72 6d 2e 72 65 73 6f 75 72 63 65 73 } //2 Library.LibraryForm.resources
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}
rule Trojan_BAT_Taskun_SO_MTB_2{
	meta:
		description = "Trojan:BAT/Taskun.SO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {19 8d 61 00 00 01 25 16 0f 01 28 92 00 00 0a 9c 25 17 0f 01 28 93 00 00 0a 9c 25 18 0f 01 28 94 00 00 0a 9c 0a 02 06 04 } //2
		$a_81_1 = {41 73 73 69 67 6e 6d 65 6e 74 5f 37 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //2 Assignment_7.Properties.Resources.resources
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*2) >=4
 
}
rule Trojan_BAT_Taskun_SO_MTB_3{
	meta:
		description = "Trojan:BAT/Taskun.SO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {06 08 91 07 28 2c 00 00 06 0d 09 2c 0f 00 06 08 8f 6f 00 00 01 28 2d 00 00 06 00 00 04 06 08 91 6f bf 00 00 0a 00 00 08 17 58 0c 08 03 fe 04 13 04 11 04 2d ca } //2
		$a_81_1 = {57 69 6e 64 6f 77 42 6c 69 6e 64 73 43 6c 69 65 6e 74 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //2 WindowBlindsClient.Properties.Resources.resources
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*2) >=4
 
}