
rule Trojan_AndroidOS_Ermac_IO{
	meta:
		description = "Trojan:AndroidOS/Ermac.IO,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {73 77 61 70 53 6d 73 4d 65 6e 61 67 65 72 5f 45 72 72 6f 72 } //1 swapSmsMenager_Error
		$a_01_1 = {75 70 64 61 74 65 53 65 74 74 69 6e 67 73 41 6e 64 43 6f 6d 6d 61 6e 64 73 } //1 updateSettingsAndCommands
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}