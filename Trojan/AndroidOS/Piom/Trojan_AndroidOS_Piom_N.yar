
rule Trojan_AndroidOS_Piom_N{
	meta:
		description = "Trojan:AndroidOS/Piom.N,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {4e 65 65 64 48 69 64 65 41 6c 6c 43 68 65 63 6b 65 64 41 70 70 } //02 00  NeedHideAllCheckedApp
		$a_01_1 = {53 43 41 4e 5f 50 52 4f 43 45 53 53 5f 52 45 53 55 4c 54 5f 54 59 50 45 5f 51 55 49 43 4b 5f 53 48 4f 57 } //02 00  SCAN_PROCESS_RESULT_TYPE_QUICK_SHOW
		$a_01_2 = {73 65 74 48 61 73 55 73 65 4d 65 6d 6f 72 79 50 65 72 63 65 6e 74 } //00 00  setHasUseMemoryPercent
	condition:
		any of ($a_*)
 
}