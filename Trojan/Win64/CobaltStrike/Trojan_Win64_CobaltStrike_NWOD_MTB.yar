
rule Trojan_Win64_CobaltStrike_NWOD_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.NWOD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 c6 43 80 fc 41 c6 43 81 d1 41 c6 43 82 d6 41 c6 43 83 17 41 c6 43 84 c4 41 c6 43 85 97 41 c6 43 86 62 41 c6 43 87 a0 41 c6 43 88 3b 41 c6 43 89 2e 41 c6 43 8a c7 41 c6 43 8b 5a 41 c6 43 8c 72 41 c6 43 8d 40 41 c6 43 8e 33 41 c6 43 8f 01 41 c6 43 90 1c } //00 00 
	condition:
		any of ($a_*)
 
}