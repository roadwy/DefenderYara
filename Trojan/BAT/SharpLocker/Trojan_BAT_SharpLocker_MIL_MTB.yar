
rule Trojan_BAT_SharpLocker_MIL_MTB{
	meta:
		description = "Trojan:BAT/SharpLocker.MIL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {73 21 00 00 06 25 02 7d 90 01 04 25 11 90 01 01 11 90 01 01 9a 90 01 1a 11 90 01 01 17 58 13 90 01 01 11 90 01 01 11 90 01 01 8e 69 32 c6 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}