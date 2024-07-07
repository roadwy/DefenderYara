
rule Trojan_AndroidOS_Ahmythspy_C{
	meta:
		description = "Trojan:AndroidOS/Ahmythspy.C,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {2f 61 70 69 2f 64 65 66 61 75 6c 74 2d 64 69 61 6c 65 72 } //1 /api/default-dialer
		$a_00_1 = {49 4e 43 4f 4d 49 4e 47 5f 43 41 4c 4c 5f 53 54 41 54 45 5f 49 44 4c 45 } //1 INCOMING_CALL_STATE_IDLE
		$a_00_2 = {2f 61 70 69 2f 76 32 2f 61 6c 61 72 6d 2f 65 6e 64 63 61 6c 6c 2f } //1 /api/v2/alarm/endcall/
		$a_00_3 = {49 4e 43 4f 4d 49 4e 47 5f 43 41 4c 4c 5f 53 54 41 54 45 5f 4f 46 46 48 4f 4f 4b } //1 INCOMING_CALL_STATE_OFFHOOK
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}