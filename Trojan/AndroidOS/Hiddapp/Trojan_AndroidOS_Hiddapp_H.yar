
rule Trojan_AndroidOS_Hiddapp_H{
	meta:
		description = "Trojan:AndroidOS/Hiddapp.H,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {53 48 4f 57 5f 55 53 45 52 5f 56 50 5f 45 58 50 49 52 45 } //02 00  SHOW_USER_VP_EXPIRE
		$a_01_1 = {4f 50 45 4e 5f 4d 49 44 44 4c 45 5f 41 44 5f 4d 4b } //02 00  OPEN_MIDDLE_AD_MK
		$a_01_2 = {56 50 5f 50 52 4f 4d 4f 54 45 5f 50 49 43 } //00 00  VP_PROMOTE_PIC
	condition:
		any of ($a_*)
 
}