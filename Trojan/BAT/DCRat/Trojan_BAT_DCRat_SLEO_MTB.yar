
rule Trojan_BAT_DCRat_SLEO_MTB{
	meta:
		description = "Trojan:BAT/DCRat.SLEO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 "
		
	strings :
		$a_81_0 = {44 61 72 6b 43 72 79 73 74 61 6c 20 52 41 54 } //5 DarkCrystal RAT
		$a_81_1 = {53 6f 6d 65 74 68 69 6e 67 20 69 73 20 66 69 73 68 79 2e 20 5b 7b 30 7d 5d } //5 Something is fishy. [{0}]
		$a_81_2 = {5b 53 63 72 65 65 6e 73 68 6f 74 5d 20 53 61 76 69 6e 67 20 73 63 72 65 65 6e 73 68 6f 74 73 20 66 72 6f 6d } //1 [Screenshot] Saving screenshots from
		$a_81_3 = {5b 43 6c 69 70 62 6f 61 72 64 5d 20 53 61 76 69 6e 67 20 69 6e 66 6f 72 6d 61 74 69 6f 6e 2e 2e 2e } //1 [Clipboard] Saving information...
		$a_81_4 = {5b 53 79 73 74 65 6d 49 6e 66 72 6f 6d 61 74 69 6f 6e 5d 20 53 61 76 69 6e 67 20 69 6e 66 6f 72 6d 61 74 69 6f 6e 2e 2e 2e } //1 [SystemInfromation] Saving information...
	condition:
		((#a_81_0  & 1)*5+(#a_81_1  & 1)*5+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=13
 
}