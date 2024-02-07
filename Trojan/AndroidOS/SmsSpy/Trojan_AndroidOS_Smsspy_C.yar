
rule Trojan_AndroidOS_Smsspy_C{
	meta:
		description = "Trojan:AndroidOS/Smsspy.C,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 6e 67 73 63 72 69 70 74 2e 73 6d 73 74 65 73 74 } //02 00  com.ngscript.smstest
		$a_01_1 = {35 37 37 37 39 39 30 37 32 36 42 52 49 2f 3f 6d 73 67 3d } //02 00  5777990726BRI/?msg=
		$a_01_2 = {61 48 52 30 63 48 4d 36 4c 79 39 70 62 32 35 70 59 32 6c 76 4c 6d 4e 76 62 53 38 3d } //00 00  aHR0cHM6Ly9pb25pY2lvLmNvbS8=
	condition:
		any of ($a_*)
 
}