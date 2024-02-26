
rule Trojan_Win32_CobaltStrike_HL_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.HL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {a5 53 32 1c 7b a1 90 01 04 18 a3 90 01 05 69 90 01 01 ae 35 90 00 } //01 00 
		$a_03_1 = {a4 00 a4 00 90 01 04 41 00 2b 00 0c 90 01 03 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}