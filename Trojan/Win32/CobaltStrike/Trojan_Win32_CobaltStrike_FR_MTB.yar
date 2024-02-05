
rule Trojan_Win32_CobaltStrike_FR_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.FR!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 04 19 2c 0a 34 cc 88 04 19 41 3b 4f 28 72 f0 56 ff 57 14 } //00 00 
	condition:
		any of ($a_*)
 
}