
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
rule Trojan_BAT_Formbook_AZ_MTB_2{
	meta:
		description = "Trojan:BAT/Formbook.AZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {95 58 20 ff 00 00 00 5f 13 18 09 11 17 07 11 17 91 11 04 11 18 95 61 28 ?? 00 00 0a 9c 00 11 17 17 58 13 17 11 17 09 8e 69 fe 04 } //4
		$a_01_1 = {34 00 38 00 46 00 57 00 37 00 43 00 34 00 38 00 45 00 46 00 42 00 48 00 35 00 38 00 43 00 39 00 5a 00 46 00 35 00 37 00 31 00 34 00 } //1 48FW7C48EFBH58C9ZF5714
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}