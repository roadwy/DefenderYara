
rule Trojan_AndroidOS_SpyAgent_BJ{
	meta:
		description = "Trojan:AndroidOS/SpyAgent.BJ,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {41 43 54 49 56 49 54 59 5f 52 45 5f 50 45 52 4d 49 53 53 49 4f 4e } //2 ACTIVITY_RE_PERMISSION
		$a_01_1 = {41 43 54 49 56 49 54 59 5f 49 47 4e 4f 52 45 5f 41 43 43 45 53 53 49 42 49 4c 49 54 59 } //2 ACTIVITY_IGNORE_ACCESSIBILITY
		$a_01_2 = {41 43 54 49 56 49 54 59 5f 4d 41 49 4e 5f 46 49 4e 49 53 48 5f 54 41 53 4b } //2 ACTIVITY_MAIN_FINISH_TASK
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}