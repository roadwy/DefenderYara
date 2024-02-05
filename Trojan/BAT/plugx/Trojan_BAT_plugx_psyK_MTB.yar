
rule Trojan_BAT_plugx_psyK_MTB{
	meta:
		description = "Trojan:BAT/plugx.psyK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 07 00 "
		
	strings :
		$a_01_0 = {19 2c 0d 72 1d 00 00 70 2b 08 2b 0d 2b 12 2b 17 de 1b 28 06 00 00 06 2b f1 28 01 00 00 2b 2b ec 28 02 00 00 2b 2b e7 0a 2b e6 } //00 00 
	condition:
		any of ($a_*)
 
}