
rule Trojan_BAT_Vidar_NH_MTB{
	meta:
		description = "Trojan:BAT/Vidar.NH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {25 26 0c 08 20 90 01 02 00 00 28 90 01 02 00 0a 25 26 0d 09 28 90 01 02 00 0a 25 26 13 04 11 04 28 90 01 02 00 0a 90 00 } //5
		$a_01_1 = {49 6e 61 63 74 74 79 72 61 6e 74 73 } //1 Inacttyrants
		$a_01_2 = {42 77 77 37 34 } //1 Bww74
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}