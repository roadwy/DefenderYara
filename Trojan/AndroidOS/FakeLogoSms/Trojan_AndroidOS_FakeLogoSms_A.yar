
rule Trojan_AndroidOS_FakeLogoSms_A{
	meta:
		description = "Trojan:AndroidOS/FakeLogoSms.A,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {d0 9b d0 b8 d0 b1 d0 be 20 d0 bf d0 b5 d1 80 d0 b5 d0 b9 d1 82 d0 b8 20 d0 bf d1 80 d1 8f d0 bc d0 be 20 d0 b8 d0 b7 20 53 4d 53 2e } //01 00 
		$a_01_1 = {70 75 73 68 6d 65 2f 61 6e 64 72 6f 69 64 2f 50 75 73 68 6d 65 } //01 00  pushme/android/Pushme
		$a_01_2 = {61 70 70 5f 6e 61 6d 65 5f 73 6b 61 79 70 65 } //01 00  app_name_skaype
		$a_01_3 = {50 75 73 68 6d 65 2e 6a 61 76 61 } //01 00  Pushme.java
		$a_01_4 = {72 75 6c 65 73 2e 68 74 6d } //00 00  rules.htm
	condition:
		any of ($a_*)
 
}