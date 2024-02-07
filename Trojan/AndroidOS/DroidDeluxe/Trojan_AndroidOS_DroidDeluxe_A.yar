
rule Trojan_AndroidOS_DroidDeluxe_A{
	meta:
		description = "Trojan:AndroidOS/DroidDeluxe.A,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 70 6f 63 6b 65 74 6c 75 78 75 73 2e 72 65 63 6f 76 65 72 79 2f 70 61 73 73 77 6f 72 64 } //01 00  com.pocketluxus.recovery/password
		$a_01_1 = {46 41 4b 45 5f 44 4f 4d 41 49 4e 5f 48 41 53 48 } //01 00  FAKE_DOMAIN_HASH
		$a_01_2 = {42 55 53 59 5f 46 49 4c 45 } //01 00  BUSY_FILE
		$a_01_3 = {55 41 2d 31 39 36 37 30 37 39 33 2d 31 } //01 00  UA-19670793-1
		$a_01_4 = {5f 5f 23 23 47 4f 4f 47 4c 45 50 41 47 45 56 49 45 57 23 23 5f 5f } //00 00  __##GOOGLEPAGEVIEW##__
	condition:
		any of ($a_*)
 
}