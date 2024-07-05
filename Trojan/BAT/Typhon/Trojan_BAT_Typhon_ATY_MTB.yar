
rule Trojan_BAT_Typhon_ATY_MTB{
	meta:
		description = "Trojan:BAT/Typhon.ATY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {54 79 70 68 6f 6e 2e 53 74 65 61 6c 65 72 2e 53 6f 66 74 77 61 72 65 2e 56 50 4e } //01 00  Typhon.Stealer.Software.VPN
		$a_01_1 = {54 79 70 68 6f 6e 2e 53 74 65 61 6c 65 72 2e 53 6f 66 74 77 61 72 65 2e 42 72 6f 77 73 65 72 73 2e 45 64 67 65 } //01 00  Typhon.Stealer.Software.Browsers.Edge
		$a_01_2 = {37 62 38 32 64 38 33 65 2d 36 31 61 61 2d 34 30 31 65 2d 61 31 30 34 2d 66 65 63 63 39 30 35 64 66 39 39 65 } //00 00  7b82d83e-61aa-401e-a104-fecc905df99e
	condition:
		any of ($a_*)
 
}