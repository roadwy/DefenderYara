
rule Trojan_AndroidOS_Placms_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Placms.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {6d 6d 5f 70 61 79 } //01 00  mm_pay
		$a_03_1 = {4c 63 6f 6d 90 02 14 50 61 79 53 74 61 74 75 73 90 00 } //01 00 
		$a_00_2 = {64 65 62 75 67 5f 62 6f 6f 74 5f 70 61 79 } //01 00  debug_boot_pay
		$a_01_3 = {49 73 63 68 65 63 6b 4e 75 6d 62 65 72 } //01 00  IscheckNumber
		$a_00_4 = {73 70 2f 73 65 6e 64 6e 75 6d 2e 78 6d 6c } //01 00  sp/sendnum.xml
		$a_01_5 = {4b 49 4c 4c 20 53 4d 53 20 49 53 20 4f 4b } //00 00  KILL SMS IS OK
		$a_00_6 = {5d 04 00 00 } //18 8f 
	condition:
		any of ($a_*)
 
}