
rule Trojan_AndroidOS_OpFakeSms_B{
	meta:
		description = "Trojan:AndroidOS/OpFakeSms.B,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 45 51 55 45 53 54 5f 53 55 43 43 45 53 } //01 00  REQUEST_SUCCES
		$a_01_1 = {66 69 72 73 74 5f 61 63 74 69 76 69 74 79 } //01 00  first_activity
		$a_01_2 = {73 75 63 63 65 73 2e 74 78 74 } //01 00  succes.txt
		$a_01_3 = {53 75 63 63 65 73 41 63 74 69 76 69 74 79 2e 6a 61 76 61 } //01 00  SuccesActivity.java
		$a_01_4 = {69 73 4e 65 65 64 53 65 6e 64 53 6d 73 4d 65 73 73 61 67 65 } //00 00  isNeedSendSmsMessage
	condition:
		any of ($a_*)
 
}
rule Trojan_AndroidOS_OpFakeSms_B_2{
	meta:
		description = "Trojan:AndroidOS/OpFakeSms.B,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {4c 65 72 68 38 2f 6e 6d 6d 36 2f 42 53 65 72 76 69 63 65 } //01 00  Lerh8/nmm6/BService
		$a_01_1 = {4c 6e 75 75 36 34 33 2f 4a 4a 4b 37 33 66 2f 4e 6a 6a 6b 72 65 68 3b } //01 00  Lnuu643/JJK73f/Njjkreh;
		$a_01_2 = {4c 64 73 72 68 6b 69 2f 79 6a 67 66 71 6a 65 6a 6b 6a 68 2f 6e 6c 72 73 6b 67 62 6c 63 3b } //01 00  Ldsrhki/yjgfqjejkjh/nlrskgblc;
		$a_01_3 = {4c 76 62 6b 6f 78 68 2f 63 73 77 6e 70 72 2f 63 6a 62 6d 74 66 77 64 79 3b } //01 00  Lvbkoxh/cswnpr/cjbmtfwdy;
		$a_01_4 = {4c 70 33 34 64 63 33 39 66 64 2f 70 31 66 34 63 30 30 65 35 2f 70 34 30 31 35 65 39 63 65 3b } //01 00  Lp34dc39fd/p1f4c00e5/p4015e9ce;
		$a_01_5 = {4c 70 39 37 63 39 64 35 38 61 2f 70 64 32 33 62 31 32 65 65 2f 70 62 64 30 34 34 64 30 33 3b } //00 00  Lp97c9d58a/pd23b12ee/pbd044d03;
	condition:
		any of ($a_*)
 
}