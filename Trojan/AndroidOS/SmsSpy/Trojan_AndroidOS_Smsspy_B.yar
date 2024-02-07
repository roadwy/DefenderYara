
rule Trojan_AndroidOS_Smsspy_B{
	meta:
		description = "Trojan:AndroidOS/Smsspy.B,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {4c 63 6f 6d 2f 76 76 2f 76 6f 64 61 66 6f 6e 65 2f 70 6f 73 74 5f 64 61 74 61 3b } //02 00  Lcom/vv/vodafone/post_data;
		$a_01_1 = {73 74 32 34 39 33 37 2e 69 73 70 6f 74 2e 63 63 2f 70 61 79 6c 6f 61 64 35 2f } //02 00  st24937.ispot.cc/payload5/
		$a_01_2 = {67 65 74 5f 70 72 69 6d 5f 70 68 6f 6e 65 } //00 00  get_prim_phone
	condition:
		any of ($a_*)
 
}