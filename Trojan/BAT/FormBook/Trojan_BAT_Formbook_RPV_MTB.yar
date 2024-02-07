
rule Trojan_BAT_Formbook_RPV_MTB{
	meta:
		description = "Trojan:BAT/Formbook.RPV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_03_0 = {31 00 39 00 38 00 2e 00 34 00 36 00 2e 00 31 00 33 00 32 00 2e 00 31 00 37 00 38 00 2f 00 90 02 30 2e 00 62 00 6d 00 70 00 90 00 } //01 00 
		$a_01_1 = {52 65 76 65 72 73 65 } //01 00  Reverse
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //01 00  DownloadData
		$a_01_3 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_01_4 = {47 65 74 4d 65 74 68 6f 64 } //01 00  GetMethod
		$a_01_5 = {43 72 65 61 74 65 44 65 6c 65 67 61 74 65 } //01 00  CreateDelegate
		$a_01_6 = {57 72 69 74 65 4c 69 6e 65 } //01 00  WriteLine
		$a_01_7 = {47 65 74 49 6e 76 6f 63 61 74 69 6f 6e 4c 69 73 74 } //01 00  GetInvocationList
		$a_01_8 = {44 79 6e 61 6d 69 63 49 6e 76 6f 6b 65 } //00 00  DynamicInvoke
	condition:
		any of ($a_*)
 
}