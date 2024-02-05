
rule Trojan_Win32_CobaltStrike_SG_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.SG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {2b ca 01 48 90 01 01 81 c2 90 01 04 8b 88 90 01 04 8b a8 90 01 04 33 cd 33 48 90 01 01 81 f1 90 01 04 8b b8 90 01 04 89 48 90 01 01 8b 48 90 01 01 81 c1 90 01 04 ff 40 90 01 01 0f af 88 90 01 04 89 88 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}