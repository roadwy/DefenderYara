
rule Trojan_BAT_Remcos_MBV_MTB{
	meta:
		description = "Trojan:BAT/Remcos.MBV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 04 11 06 1f 28 5a 58 13 07 11 07 } //1 Бؑ⠟塚ܓܑ
		$a_01_1 = {45 50 78 00 4e 37 6f 37 73 34 4d 33 56 57 34 55 53 66 74 76 47 45 00 45 39 6f 31 35 77 69 44 6b 6f 48 66 45 79 66 31 5a 41 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}