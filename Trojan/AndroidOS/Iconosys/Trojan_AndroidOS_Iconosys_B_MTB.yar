
rule Trojan_AndroidOS_Iconosys_B_MTB{
	meta:
		description = "Trojan:AndroidOS/Iconosys.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 08 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 65 6e 64 50 68 6f 6e 65 44 61 74 61 } //01 00  SendPhoneData
		$a_00_1 = {67 65 74 50 68 6f 6e 65 4e 75 6d 62 65 72 73 } //01 00  getPhoneNumbers
		$a_00_2 = {62 6c 61 63 6b 66 6c 79 64 61 79 2e 63 6f 6d 2f 6e 65 77 2f } //01 00  blackflyday.com/new/
		$a_00_3 = {73 6d 73 72 65 70 6c 69 65 72 2e 6e 65 74 2f 73 6d 73 72 65 70 6c 79 } //01 00  smsreplier.net/smsreply
		$a_00_4 = {62 75 7a 7a 67 65 6f 64 61 74 61 2e 70 68 70 } //01 00  buzzgeodata.php
		$a_00_5 = {72 65 67 61 6e 64 77 65 6c 63 6f 6d 65 2e 70 68 70 } //01 00  regandwelcome.php
		$a_00_6 = {53 65 6e 64 50 68 6f 6e 65 47 65 6f 44 61 74 61 } //01 00  SendPhoneGeoData
		$a_00_7 = {72 65 61 6c 70 68 6f 6e 65 6e 6f } //00 00  realphoneno
	condition:
		any of ($a_*)
 
}