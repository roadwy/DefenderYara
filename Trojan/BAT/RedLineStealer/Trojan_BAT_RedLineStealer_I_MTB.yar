
rule Trojan_BAT_RedLineStealer_I_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.I!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {06 16 06 8e 69 28 90 01 01 00 00 06 13 05 16 2d 18 7e 90 00 } //02 00 
		$a_01_1 = {68 64 66 66 66 66 68 66 61 73 64 6b 66 73 68 } //00 00  hdffffhfasdkfsh
	condition:
		any of ($a_*)
 
}