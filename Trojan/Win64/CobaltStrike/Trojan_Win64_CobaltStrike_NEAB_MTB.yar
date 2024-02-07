
rule Trojan_Win64_CobaltStrike_NEAB_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.NEAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {2b c1 48 63 c8 48 8b 44 24 68 42 8a 8c 31 30 49 00 00 41 32 0c 00 41 88 0c 18 49 ff c0 3b 6c 24 60 72 c2 } //05 00 
		$a_01_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 6d 00 73 00 75 00 6e 00 2e 00 72 00 75 00 } //00 00  http://msun.ru
	condition:
		any of ($a_*)
 
}