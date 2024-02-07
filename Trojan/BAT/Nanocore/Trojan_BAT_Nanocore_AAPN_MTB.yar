
rule Trojan_BAT_Nanocore_AAPN_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.AAPN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {51 75 65 73 74 69 6f 6e 73 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //01 00  Questions.Properties.Resources.resources
		$a_01_1 = {31 61 32 66 32 33 32 39 2d 37 62 63 35 2d 34 36 31 64 2d 62 39 65 32 2d 33 64 38 61 35 66 30 38 30 38 31 39 } //00 00  1a2f2329-7bc5-461d-b9e2-3d8a5f080819
	condition:
		any of ($a_*)
 
}