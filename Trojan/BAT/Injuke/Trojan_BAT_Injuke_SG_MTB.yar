
rule Trojan_BAT_Injuke_SG_MTB{
	meta:
		description = "Trojan:BAT/Injuke.SG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {72 8b 00 00 70 28 1b 00 00 0a 72 95 00 00 70 28 1c 00 00 0a } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Injuke_SG_MTB_2{
	meta:
		description = "Trojan:BAT/Injuke.SG!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {47 65 74 44 6f 6d 61 69 6e } //01 00  GetDomain
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //02 00  CreateDecryptor
		$a_01_2 = {73 69 6d 70 6c 65 43 41 6c 63 75 6c 61 74 6f 72 45 78 63 65 70 74 69 6f 6e 5f 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //00 00  simpleCAlculatorException_.Properties.Resources
	condition:
		any of ($a_*)
 
}