
rule Trojan_BAT_Vidar_PSRE_MTB{
	meta:
		description = "Trojan:BAT/Vidar.PSRE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {2b 09 28 a6 a6 6b 3e 14 16 9a 26 16 2d f9 fe 09 00 00 fe 09 01 00 fe 09 02 00 fe 09 03 00 6f 7a 00 00 0a 2a } //00 00 
	condition:
		any of ($a_*)
 
}