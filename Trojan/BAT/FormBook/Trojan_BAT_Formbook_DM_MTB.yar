
rule Trojan_BAT_Formbook_DM_MTB{
	meta:
		description = "Trojan:BAT/Formbook.DM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {24 37 33 33 65 37 35 37 63 2d 66 63 30 33 2d 34 64 34 35 2d 39 31 39 30 2d 64 37 36 39 65 37 61 63 32 65 39 34 } //1 $733e757c-fc03-4d45-9190-d769e7ac2e94
		$a_81_1 = {42 61 63 6b 75 70 20 53 75 63 63 65 73 73 66 75 6c 6c 79 20 52 65 73 74 6f 72 65 64 21 21 21 } //1 Backup Successfully Restored!!!
		$a_81_2 = {50 61 74 68 6f 6c 6f 67 79 2e 52 65 73 6f 75 72 63 65 73 } //1 Pathology.Resources
		$a_81_3 = {53 74 6f 63 6b 4d 61 73 74 65 72 } //1 StockMaster
		$a_81_4 = {50 61 74 69 65 6e 74 5f 4d 61 73 74 65 72 } //1 Patient_Master
		$a_81_5 = {44 69 73 65 61 73 65 4d 73 74 72 } //1 DiseaseMstr
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}