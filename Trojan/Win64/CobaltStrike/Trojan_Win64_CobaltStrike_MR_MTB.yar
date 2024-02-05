
rule Trojan_Win64_CobaltStrike_MR_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 05 00 "
		
	strings :
		$a_01_0 = {f0 00 23 00 0b 02 0e 1d 00 c0 08 00 00 c0 97 01 00 00 00 00 50 c8 eb 04 00 10 } //05 00 
		$a_01_1 = {f0 00 23 00 0b 02 0e 1d 00 bc 08 00 00 86 66 00 00 00 00 00 1b 23 7d 02 00 10 } //05 00 
		$a_01_2 = {f0 00 23 00 0b 02 0e 1d 00 c6 08 00 00 ce eb 01 00 00 00 00 b8 eb 8d 05 00 10 } //00 00 
	condition:
		any of ($a_*)
 
}