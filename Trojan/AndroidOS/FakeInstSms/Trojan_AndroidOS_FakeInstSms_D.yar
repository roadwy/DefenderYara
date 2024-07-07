
rule Trojan_AndroidOS_FakeInstSms_D{
	meta:
		description = "Trojan:AndroidOS/FakeInstSms.D,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {22 01 a7 01 70 10 25 08 01 00 22 02 a4 01 22 03 7f 01 1a 04 11 05 70 20 c6 07 43 00 54 a4 72 02 6e 10 a8 06 04 00 0c 04 6e 20 cb 07 43 00 0c 03 1a 04 77 00 6e 20 cb 07 43 00 0c 03 12 04 46 04 0b 04 6e 20 cb 07 43 00 0c 03 1a 04 82 } //1
		$a_01_1 = {0c 03 1a 04 7d 00 6e 20 cb 07 43 00 0c 03 6e 20 cb 07 23 00 0c 02 1a 03 79 00 6e 20 cb 07 32 00 0c 02 6e 20 cb 07 12 00 0c 01 1a 02 75 00 } //1
		$a_01_2 = {68 74 74 70 3a 2f 2f 61 70 70 73 2e 73 65 78 75 72 75 73 2e 63 6f 6d 2f 70 68 70 2f 69 6e 64 65 78 2e 70 68 70 2f 3f 74 61 67 3d 75 73 65 72 73 61 76 65 26 75 73 65 72 6e 61 6d 65 3d } //1 http://apps.sexurus.com/php/index.php/?tag=usersave&username=
		$a_01_3 = {26 6e 75 6d 65 72 6f 3d } //1 &numero=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}