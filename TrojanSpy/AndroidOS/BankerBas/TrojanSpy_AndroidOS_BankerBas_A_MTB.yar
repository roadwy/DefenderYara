
rule TrojanSpy_AndroidOS_BankerBas_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/BankerBas.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {61 6e 79 77 68 65 72 65 73 6f 66 74 77 61 72 65 2e 62 34 61 } //01 00  anywheresoftware.b4a
		$a_00_1 = {75 72 6f 73 5f 35 2e 73 6d 73 5f 61 6e 64 5f 63 6f 6e 74 61 63 74 73 } //01 00  uros_5.sms_and_contacts
		$a_00_2 = {61 72 65 20 79 6f 75 20 64 72 69 6e 6b 69 6e 67 } //01 00  are you drinking
		$a_00_3 = {44 69 64 20 79 6f 75 20 66 6f 72 67 65 74 20 74 6f 20 63 61 6c 6c 20 41 63 74 69 76 69 74 79 } //00 00  Did you forget to call Activity
	condition:
		any of ($a_*)
 
}