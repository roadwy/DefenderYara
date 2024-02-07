
rule Trojan_AndroidOS_funkyBot_B{
	meta:
		description = "Trojan:AndroidOS/funkyBot.B,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {69 6e 20 66 69 6e 64 44 65 78 20 73 74 61 72 74 } //01 00  in findDex start
		$a_00_1 = {63 73 6e 5f } //01 00  csn_
		$a_01_2 = {61 70 70 5f 63 73 6e 30 2f 2e 75 6e 7a 69 70 2f 6f 61 74 } //01 00  app_csn0/.unzip/oat
		$a_01_3 = {2e 63 73 6e 2e 64 65 78 } //01 00  .csn.dex
		$a_01_4 = {2e 75 6e 7a 69 70 2f 64 2d 63 6c 61 73 73 65 73 2e 64 65 78 } //01 00  .unzip/d-classes.dex
		$a_01_5 = {63 6f 6d 2f 73 65 63 75 72 69 74 79 2f 73 68 65 6c 6c 2f 4a 4e 49 54 6f 6f 6c 73 } //02 00  com/security/shell/JNITools
		$a_00_6 = {80 b5 6f 46 8a b0 13 46 8c 46 86 46 09 90 08 91 07 92 08 98 02 93 cd f8 04 c0 cd f8 00 e0 ff f7 12 e8 06 90 51 20 07 f8 11 0c 08 98 40 08 04 90 04 98 08 99 88 42 03 d9 ff e7 08 98 04 90 ff e7 00 20 03 90 ff e7 03 98 08 99 88 42 19 d2 ff e7 03 98 04 99 88 42 09 d2 ff e7 09 98 03 99 40 5c 17 f8 11 2c 50 40 06 9a 50 54 05 e0 } //00 00 
	condition:
		any of ($a_*)
 
}