
rule Trojan_Win32_CobaltStrike_AB_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {80 34 19 39 41 3b ce 72 f7 } //00 00 
	condition:
		any of ($a_*)
 
}