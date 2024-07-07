
rule Trojan_BAT_Formbook_AZ_MTB{
	meta:
		description = "Trojan:BAT/Formbook.AZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {48 59 54 47 4b 4d 6e 2e 70 64 62 } //2 HYTGKMn.pdb
		$a_01_1 = {48 59 54 47 4b 4d 6e 2e 50 72 6f 70 65 72 74 69 65 73 } //2 HYTGKMn.Properties
		$a_01_2 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
		$a_01_3 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}