
rule Trojan_Win32_CobaltStrike_TD_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.TD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {88 0c 38 8b cf 8b 7c 24 18 0f b6 04 0e 03 c2 0f b6 c0 8a 04 08 32 04 1f 88 03 43 8b 44 24 20 83 ed 01 75 } //00 00 
	condition:
		any of ($a_*)
 
}