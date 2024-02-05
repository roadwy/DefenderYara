
rule Adware_Win64_OffersWizardInstaller{
	meta:
		description = "Adware:Win64/OffersWizardInstaller,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 69 73 70 6c 61 79 4e 61 6d 65 00 4f 66 66 65 72 73 57 69 7a 61 72 64 20 4e 65 74 77 6f 72 6b 20 53 79 73 74 65 6d 20 44 72 69 76 65 72 } //01 00 
		$a_01_1 = {6e 65 74 68 74 73 72 76 2e 65 78 65 22 20 2d 6e 66 64 69 20 2f 72 76 6d } //01 00 
		$a_01_2 = {02 25 25 5c 64 72 69 76 65 72 73 00 6e 65 74 68 66 64 72 76 2e 73 79 73 } //00 00 
	condition:
		any of ($a_*)
 
}