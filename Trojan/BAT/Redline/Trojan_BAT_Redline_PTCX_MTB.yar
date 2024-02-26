
rule Trojan_BAT_Redline_PTCX_MTB{
	meta:
		description = "Trojan:BAT/Redline.PTCX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {74 26 00 00 1b 08 28 90 01 01 00 00 0a 28 90 01 01 01 00 06 14 72 db 02 00 70 16 8d 04 00 00 01 14 14 14 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a a2 72 b9 06 00 70 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}