
rule Trojan_Win32_CobaltStrike_ACL_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.ACL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {6a 00 6a 00 6a 03 6a 00 6a 00 68 28 03 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}