
rule Trojan_AndroidOS_SMSFakeSky_A{
	meta:
		description = "Trojan:AndroidOS/SMSFakeSky.A,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {4b 77 72 68 52 65 63 65 69 76 65 52 2e 6a 61 76 61 } //01 00  KwrhReceiveR.java
		$a_01_1 = {43 68 65 63 6b 69 6e 67 20 66 6f 72 20 73 65 6e 64 69 6e 67 20 61 6e 6f 74 68 65 72 20 53 4d 53 2e } //01 00  Checking for sending another SMS.
		$a_01_2 = {72 61 77 2f 64 61 74 61 2e 64 61 74 } //01 00  raw/data.dat
		$a_01_3 = {61 6e 64 72 6f 69 64 5f 61 73 73 65 74 2f 74 65 73 74 2e 68 74 6d 6c 23 6c 6f 61 64 65 64 3d } //00 00  android_asset/test.html#loaded=
	condition:
		any of ($a_*)
 
}