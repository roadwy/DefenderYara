
rule Trojan_BAT_SheetCreep_GVA_MTB{
	meta:
		description = "Trojan:BAT/SheetCreep.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {72 8d 00 00 70 03 72 97 00 00 70 28 0d 00 00 0a 6f 0e 00 00 0a } //1
		$a_00_1 = {43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 50 00 75 00 62 00 6c 00 69 00 63 00 5c 00 44 00 6f 00 63 00 75 00 6d 00 65 00 6e 00 74 00 73 00 5c 00 } //1 C:\Users\Public\Documents\
		$a_00_2 = {47 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 2e 00 70 00 6e 00 67 00 } //2 GServices.png
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*2) >=4
 
}