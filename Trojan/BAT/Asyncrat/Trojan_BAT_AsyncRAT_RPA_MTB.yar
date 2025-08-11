
rule Trojan_BAT_AsyncRAT_RPA_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.RPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,6e 00 6e 00 0b 00 00 "
		
	strings :
		$a_01_0 = {63 6f 70 6f 73 50 72 6f 6a 65 63 74 2e 66 6f 72 67 6f 74 70 61 73 73 77 6f 72 64 46 6f 72 6d 2e 72 65 73 6f 75 72 63 65 73 } //1 coposProject.forgotpasswordForm.resources
		$a_01_1 = {63 6f 70 6f 73 50 72 6f 6a 65 63 74 2e 73 74 61 74 69 73 74 69 63 73 46 6f 72 6d 2e 72 65 73 6f 75 72 63 65 73 } //1 coposProject.statisticsForm.resources
		$a_01_2 = {63 6f 70 6f 73 50 72 6f 6a 65 63 74 2e 68 69 73 74 6f 72 79 46 6f 72 6d 2e 72 65 73 6f 75 72 63 65 73 } //1 coposProject.historyForm.resources
		$a_01_3 = {63 6f 70 6f 73 50 72 6f 6a 65 63 74 2e 73 74 61 72 74 46 6f 72 6d 54 77 6f 2e 72 65 73 6f 75 72 63 65 73 } //1 coposProject.startFormTwo.resources
		$a_01_4 = {63 6f 70 6f 73 50 72 6f 6a 65 63 74 2e 73 74 61 72 74 46 6f 72 6d 54 68 72 65 65 2e 72 65 73 6f 75 72 63 65 73 } //1 coposProject.startFormThree.resources
		$a_01_5 = {63 6f 70 6f 73 50 72 6f 6a 65 63 74 2e 75 63 49 6e 76 65 6e 74 6f 72 79 45 6d 70 6c 6f 79 65 65 2e 72 65 73 6f 75 72 63 65 73 } //1 coposProject.ucInventoryEmployee.resources
		$a_01_6 = {63 6f 70 6f 73 50 72 6f 6a 65 63 74 2e 75 63 53 61 6c 65 73 45 6d 70 6c 6f 79 65 65 2e 72 65 73 6f 75 72 63 65 73 } //1 coposProject.ucSalesEmployee.resources
		$a_01_7 = {63 6f 70 6f 73 50 72 6f 6a 65 63 74 2e 75 63 53 61 6c 65 73 52 65 63 65 69 70 74 45 6d 70 6c 6f 79 65 65 2e 72 65 73 6f 75 72 63 65 73 } //1 coposProject.ucSalesReceiptEmployee.resources
		$a_01_8 = {63 6f 70 6f 73 50 72 6f 6a 65 63 74 2e 75 63 52 65 63 65 69 70 74 50 6f 2e 72 65 73 6f 75 72 63 65 73 } //1 coposProject.ucReceiptPo.resources
		$a_01_9 = {63 6f 70 6f 73 50 72 6f 6a 65 63 74 2e 75 63 49 6e 76 65 6e 74 6f 72 79 2e 72 65 73 6f 75 72 63 65 73 } //1 coposProject.ucInventory.resources
		$a_01_10 = {63 6f 70 6f 73 50 72 6f 6a 65 63 74 2e 75 73 65 72 43 6f 6e 74 72 6f 6c 2e 70 75 72 63 68 61 73 65 4f 72 64 65 72 55 63 2e 72 65 73 6f 75 72 63 65 73 } //100 coposProject.userControl.purchaseOrderUc.resources
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*100) >=110
 
}