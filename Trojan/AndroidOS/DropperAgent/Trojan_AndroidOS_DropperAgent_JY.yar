
rule Trojan_AndroidOS_DropperAgent_JY{
	meta:
		description = "Trojan:AndroidOS/DropperAgent.JY,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 59 53 54 45 4d 5f 57 52 49 54 45 5f 52 45 51 55 49 52 45 44 } //2 SYSTEM_WRITE_REQUIRED
		$a_01_1 = {44 49 53 50 4c 41 59 5f 4f 56 45 52 5f 41 50 50 53 5f 49 4e 53 54 41 4c 4c 5f 52 45 51 55 49 52 45 44 } //2 DISPLAY_OVER_APPS_INSTALL_REQUIRED
		$a_01_2 = {50 45 52 4d 49 53 53 49 4f 4e 5f 49 4e 53 54 41 4c 4c 5f 52 45 51 55 49 52 45 44 } //2 PERMISSION_INSTALL_REQUIRED
		$a_01_3 = {43 4d 44 5f 49 47 4e 4f 52 45 5f 42 41 54 54 45 52 59 } //2 CMD_IGNORE_BATTERY
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}