
rule Trojan_BAT_AveMariaRAT_NYJ_MTB{
	meta:
		description = "Trojan:BAT/AveMariaRAT.NYJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 00 3a 00 5c 00 54 00 65 00 66 00 73 00 64 00 64 00 64 00 64 00 64 00 6d 00 70 00 00 41 43 00 3a 00 5c 00 4e 00 65 00 64 00 64 00 64 00 64 00 64 00 64 00 64 00 64 00 64 00 64 00 64 00 64 00 64 00 64 00 64 00 64 00 64 00 64 00 64 00 64 00 64 00 64 00 77 00 54 00 65 00 6d 00 70 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AveMariaRAT_NYJ_MTB_2{
	meta:
		description = "Trojan:BAT/AveMariaRAT.NYJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {2e 00 72 00 65 00 73 00 00 09 6f 00 75 00 72 00 63 00 00 05 65 00 73 00 00 2f 53 00 53 00 4d 00 53 } //01 00 
		$a_81_1 = {53 53 4d 53 53 53 65 53 53 74 53 68 53 6f 53 53 53 64 53 53 30 53 53 } //01 00  SSMSSSeSStShSoSSSdSS0SS
		$a_81_2 = {44 65 61 74 48 } //01 00  DeatH
		$a_81_3 = {47 65 74 4d 61 6e 69 66 65 73 74 52 65 73 6f 75 72 63 65 4e 61 6d 65 73 } //01 00  GetManifestResourceNames
		$a_81_4 = {43 6f 69 73 64 68 76 70 73 64 75 79 70 73 39 38 79 76 68 61 6a 6e } //00 00  Coisdhvpsduyps98yvhajn
	condition:
		any of ($a_*)
 
}