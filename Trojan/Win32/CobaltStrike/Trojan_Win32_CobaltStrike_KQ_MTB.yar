
rule Trojan_Win32_CobaltStrike_KQ_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.KQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 85 a0 f9 90 01 02 40 89 85 90 01 04 81 bd 90 01 08 73 90 01 01 8b 85 90 01 04 0f be 8c 05 90 01 04 8b 85 90 01 04 99 f7 bd 90 01 04 0f be 44 15 90 01 01 33 c8 8b 85 90 01 04 88 8c 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}