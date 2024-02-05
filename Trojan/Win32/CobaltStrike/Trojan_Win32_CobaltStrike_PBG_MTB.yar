
rule Trojan_Win32_CobaltStrike_PBG_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.PBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {83 c2 01 89 55 f0 8b 45 f0 3b 45 0c 73 90 01 01 8b 45 f0 33 d2 b9 04 00 00 00 f7 f1 0f b6 54 15 fc 8b 45 08 03 45 f0 0f be 08 33 ca 8b 55 08 03 55 f0 88 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}