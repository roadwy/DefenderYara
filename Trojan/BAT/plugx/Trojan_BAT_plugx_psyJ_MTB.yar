
rule Trojan_BAT_plugx_psyJ_MTB{
	meta:
		description = "Trojan:BAT/plugx.psyJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 07 00 "
		
	strings :
		$a_01_0 = {72 01 00 00 70 17 8d 1c 00 00 01 25 16 1f 2d 9d 28 0d 00 00 0a 17 9a 6f 0e 00 00 0a 72 c4 00 00 70 17 } //00 00 
	condition:
		any of ($a_*)
 
}