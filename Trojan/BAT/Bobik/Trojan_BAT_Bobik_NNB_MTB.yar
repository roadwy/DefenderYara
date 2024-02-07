
rule Trojan_BAT_Bobik_NNB_MTB{
	meta:
		description = "Trojan:BAT/Bobik.NNB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 05 00 "
		
	strings :
		$a_03_0 = {6f 4c 00 00 0a 6f 90 01 01 00 00 0a 13 04 12 04 28 90 01 01 00 00 0a 1f 28 da 73 90 01 01 00 00 0a 16 16 73 90 01 01 00 00 0a 11 06 6f 90 01 01 00 00 0a 90 00 } //01 00 
		$a_01_1 = {54 61 73 6b 62 61 72 20 44 65 73 74 72 6f 79 65 72 2e 65 78 65 } //01 00  Taskbar Destroyer.exe
		$a_01_2 = {57 00 69 00 6e 00 46 00 6f 00 72 00 6d 00 73 00 5f 00 52 00 65 00 63 00 75 00 72 00 73 00 69 00 76 00 65 00 46 00 6f 00 72 00 6d 00 43 00 72 00 65 00 61 00 74 00 65 00 } //01 00  WinForms_RecursiveFormCreate
		$a_01_3 = {57 00 69 00 6e 00 46 00 6f 00 72 00 6d 00 73 00 5f 00 53 00 65 00 65 00 49 00 6e 00 6e 00 65 00 72 00 45 00 78 00 63 00 65 00 70 00 74 00 69 00 6f 00 6e 00 } //00 00  WinForms_SeeInnerException
	condition:
		any of ($a_*)
 
}