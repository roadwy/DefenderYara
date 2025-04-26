
rule Trojan_AndroidOS_Banker_U{
	meta:
		description = "Trojan:AndroidOS/Banker.U,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {73 61 76 65 5f 73 6d 73 30 2e 70 68 70 3f 70 68 6f 6e 65 3d } //2 save_sms0.php?phone=
		$a_00_1 = {61 74 6d 61 63 2e 70 68 70 } //2 atmac.php
		$a_01_2 = {53 31 6d 32 73 33 4c 34 69 35 73 36 74 37 6e 38 65 39 72 30 } //1 S1m2s3L4i5s6t7n8e9r0
		$a_01_3 = {53 31 6d 32 73 33 52 34 65 35 63 36 65 37 69 38 76 39 65 30 72 } //1 S1m2s3R4e5c6e7i8v9e0r
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}