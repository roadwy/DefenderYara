
rule Trojan_Win32_CobaltStrike_IN_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.IN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b c7 8a 49 08 80 e9 05 88 48 08 8b 47 14 83 f8 10 } //01 00 
		$a_01_1 = {8b c7 8a 51 07 fe ca 88 50 07 8b 47 14 83 f8 10 } //00 00 
	condition:
		any of ($a_*)
 
}