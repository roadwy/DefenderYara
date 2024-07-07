
rule Adware_AndroidOS_Ashas_A{
	meta:
		description = "Adware:AndroidOS/Ashas.A,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_00_0 = {41 53 48 41 53 } //2 ASHAS
		$a_00_1 = {43 4f 44 45 5f 43 4c 49 45 4e 54 5f 43 4f 4e 46 49 47 } //2 CODE_CLIENT_CONFIG
		$a_00_2 = {41 4c 41 52 4d 5f 53 43 48 45 44 55 4c 45 5f 4d 49 4e 55 54 45 53 } //2 ALARM_SCHEDULE_MINUTES
		$a_01_3 = {41 53 61 64 73 64 6b } //1 ASadsdk
		$a_00_4 = {46 69 72 73 74 52 75 6e 53 65 72 76 69 63 65 20 6f 6e 43 72 65 61 74 65 } //1 FirstRunService onCreate
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1) >=7
 
}