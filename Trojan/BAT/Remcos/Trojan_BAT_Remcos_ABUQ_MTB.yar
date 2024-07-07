
rule Trojan_BAT_Remcos_ABUQ_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ABUQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 0a 17 8d 90 01 01 00 00 01 25 16 06 74 90 01 01 00 00 1b 28 90 01 01 00 00 06 a2 2a 90 0a 2a 00 28 90 01 01 00 00 06 28 90 01 01 00 00 06 74 90 01 01 00 00 01 28 90 00 } //4
		$a_01_1 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 46 00 6f 00 72 00 6d 00 73 00 41 00 70 00 70 00 37 00 36 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 WindowsFormsApp76.Properties.Resources
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}