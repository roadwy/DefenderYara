
rule Trojan_BAT_plugx_psyE_MTB{
	meta:
		description = "Trojan:BAT/plugx.psyE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 07 00 "
		
	strings :
		$a_01_0 = {73 12 00 00 06 0a 06 28 1c 00 00 0a 7d 07 00 00 04 06 02 7d 09 00 00 04 06 03 7d 08 00 00 04 06 15 7d 06 00 00 04 06 7c 07 00 00 04 12 00 28 03 00 00 2b 06 7c 07 00 00 04 28 1e 00 00 0a 2a } //00 00 
	condition:
		any of ($a_*)
 
}