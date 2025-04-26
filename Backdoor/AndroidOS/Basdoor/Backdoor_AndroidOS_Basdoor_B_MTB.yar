
rule Backdoor_AndroidOS_Basdoor_B_MTB{
	meta:
		description = "Backdoor:AndroidOS/Basdoor.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_00_0 = {68 69 64 65 41 70 70 49 63 6f 6e } //1 hideAppIcon
		$a_00_1 = {5f 73 65 6e 64 6c 61 72 67 65 73 6d 73 } //1 _sendlargesms
		$a_00_2 = {49 20 48 61 76 65 20 41 63 63 65 73 73 20 3a 29 } //1 I Have Access :)
		$a_00_3 = {40 72 6f 6f 74 44 72 44 65 76 3a } //1 @rootDrDev:
		$a_00_4 = {67 65 74 41 6c 6c 53 4d 53 } //1 getAllSMS
		$a_00_5 = {67 65 74 63 6f 6e 74 61 63 74 73 } //1 getcontacts
		$a_00_6 = {62 6f 6d 62 } //1 bomb
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=6
 
}