
rule Adware_AndroidOS_Ewind_A{
	meta:
		description = "Adware:AndroidOS/Ewind.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {48 65 79 48 65 79 } //1 HeyHey
		$a_01_1 = {41 6c 69 76 65 45 76 65 6e 74 53 65 6e 64 41 6c 61 72 6d } //1 AliveEventSendAlarm
		$a_01_2 = {43 72 79 6f 70 69 67 67 79 41 70 70 6c 69 63 61 74 69 6f 6e } //1 CryopiggyApplication
		$a_01_3 = {69 73 49 6d 70 72 65 73 73 69 6f 6e 57 61 73 44 6f 6e 65 } //1 isImpressionWasDone
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}