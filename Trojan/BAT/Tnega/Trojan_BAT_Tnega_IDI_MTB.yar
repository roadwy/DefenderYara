
rule Trojan_BAT_Tnega_IDI_MTB{
	meta:
		description = "Trojan:BAT/Tnega.IDI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {28 0f 00 00 0a 25 72 01 00 00 70 6f 10 00 00 0a 26 25 72 75 00 00 70 6f 10 00 00 0a 26 25 72 d9 00 00 70 6f 10 00 00 0a 26 6f 11 00 00 0a 26 72 } //1
		$a_81_1 = {41 4d 52 5f 44 4f 57 4e } //1 AMR_DOWN
	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}