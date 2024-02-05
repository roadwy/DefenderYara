
rule Trojan_Win32_CobaltStrike_CD_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.CD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f be 02 33 c1 8b 4d 90 01 01 03 4d 90 01 01 88 01 8b 55 90 01 01 03 55 90 01 01 0f be 0a 03 4d 90 01 01 8b 45 90 01 01 33 d2 be 90 01 04 f7 f6 03 ca 8b c1 33 d2 b9 90 01 04 f7 f1 89 55 90 01 01 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}