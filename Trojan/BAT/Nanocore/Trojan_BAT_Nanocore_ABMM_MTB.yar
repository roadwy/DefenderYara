
rule Trojan_BAT_Nanocore_ABMM_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.ABMM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 03 00 "
		
	strings :
		$a_01_0 = {56 6f 6c 76 6f 53 36 30 2e 50 44 4f 43 6f 6e 74 72 6f 6c 73 2e 72 65 73 6f 75 72 63 65 73 } //03 00  VolvoS60.PDOControls.resources
		$a_01_1 = {56 00 6f 00 6c 00 76 00 6f 00 53 00 36 00 30 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 } //00 00 
	condition:
		any of ($a_*)
 
}