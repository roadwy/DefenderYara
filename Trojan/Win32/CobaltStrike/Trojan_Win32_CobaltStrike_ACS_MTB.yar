
rule Trojan_Win32_CobaltStrike_ACS_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.ACS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {c7 45 ec 65 00 00 00 c7 45 cc 0c 00 00 00 c7 45 d0 0c 00 00 00 c7 45 d4 0f 00 00 00 c7 45 d8 0b 00 00 00 c7 45 dc 01 00 00 00 c7 45 e0 0a 00 00 00 c7 45 e4 0d 00 00 00 c7 45 f0 } //00 00 
	condition:
		any of ($a_*)
 
}