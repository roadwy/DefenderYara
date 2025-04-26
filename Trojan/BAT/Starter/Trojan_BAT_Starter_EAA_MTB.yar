
rule Trojan_BAT_Starter_EAA_MTB{
	meta:
		description = "Trojan:BAT/Starter.EAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_81_0 = {24 4c 69 6d 65 55 53 42 5c 44 4f 4e 45 5c 45 78 70 65 6e 73 65 73 20 73 68 65 65 74 2e 78 6c 73 78 } //1 $LimeUSB\DONE\Expenses sheet.xlsx
		$a_81_1 = {24 4c 69 6d 65 55 53 42 5c 4c 69 6d 65 55 53 42 2e 65 78 65 } //1 $LimeUSB\LimeUSB.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}