
rule Trojan_Win32_CobaltStrike_CCDQ_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.CCDQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 c8 fc 40 8a 80 90 01 04 30 87 90 01 04 68 90 01 04 68 90 01 04 ff 15 90 01 04 50 ff 15 90 01 04 80 b7 90 01 05 85 c0 b8 01 00 00 00 0f 45 f0 47 3b 3d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}