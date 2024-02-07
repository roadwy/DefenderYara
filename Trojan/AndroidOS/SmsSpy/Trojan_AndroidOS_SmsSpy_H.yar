
rule Trojan_AndroidOS_SmsSpy_H{
	meta:
		description = "Trojan:AndroidOS/SmsSpy.H,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {32 39 32 30 39 64 6a 32 30 64 33 39 32 6a 33 64 6b 30 6a 69 72 6a 66 30 69 33 6a 66 32 30 33 } //01 00  29209dj20d392j3dk0jirjf0i3jf203
		$a_00_1 = {66 75 6c 6c 73 6d 73 5f 63 61 63 6f 33 33 33 } //01 00  fullsms_caco333
		$a_00_2 = {52 65 73 75 6d 61 62 6c 65 53 75 62 5f 53 65 72 76 69 63 65 5f 53 74 61 72 74 } //00 00  ResumableSub_Service_Start
	condition:
		any of ($a_*)
 
}