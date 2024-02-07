
rule Ransom_MSIL_Nitro_DA_MTB{
	meta:
		description = "Ransom:MSIL/Nitro.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {4e 69 74 72 6f 52 61 6e 73 6f 6d 77 61 72 65 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //01 00  NitroRansomware.Properties.Resources
		$a_81_1 = {66 69 6c 65 3a 2f 2f 2f } //01 00  file:///
		$a_81_2 = {52 65 70 6c 61 63 65 } //01 00  Replace
		$a_81_3 = {42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  Base64String
		$a_81_4 = {44 65 62 75 67 67 65 72 20 44 65 74 65 63 74 65 64 } //01 00  Debugger Detected
		$a_81_5 = {69 73 20 74 61 6d 70 65 72 65 64 } //00 00  is tampered
	condition:
		any of ($a_*)
 
}