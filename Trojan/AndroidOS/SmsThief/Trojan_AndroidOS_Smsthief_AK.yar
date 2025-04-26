
rule Trojan_AndroidOS_Smsthief_AK{
	meta:
		description = "Trojan:AndroidOS/Smsthief.AK,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 6f 6e 74 61 63 74 53 6d 73 41 70 70 6c 69 63 61 74 69 6f 6e } //2 ContactSmsApplication
		$a_01_1 = {6d 65 68 72 61 62 5f 6e 6f 74 69 66 5f 69 64 } //2 mehrab_notif_id
		$a_01_2 = {53 69 6d 53 6d 73 41 70 70 6c 69 63 61 74 69 6f 6e } //2 SimSmsApplication
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}