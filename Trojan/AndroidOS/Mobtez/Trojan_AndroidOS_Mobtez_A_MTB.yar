
rule Trojan_AndroidOS_Mobtez_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Mobtez.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {73 74 61 72 74 53 6d 73 46 69 6c 74 65 72 73 } //1 startSmsFilters
		$a_00_1 = {6d 61 78 53 65 6e 64 43 6f 75 6e 74 } //1 maxSendCount
		$a_00_2 = {73 65 6e 64 53 6d 73 50 65 72 69 6f 64 } //1 sendSmsPeriod
		$a_00_3 = {4f 70 65 72 61 55 70 64 61 74 65 72 41 63 74 69 76 69 74 79 } //1 OperaUpdaterActivity
		$a_00_4 = {4c 6f 72 67 2f 4d 6f 62 69 6c 65 44 62 2f 4d 6f 62 69 6c 65 44 61 74 61 62 61 73 65 } //1 Lorg/MobileDb/MobileDatabase
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}