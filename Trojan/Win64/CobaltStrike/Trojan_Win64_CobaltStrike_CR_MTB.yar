
rule Trojan_Win64_CobaltStrike_CR_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 14 02 48 ff c0 45 31 db 4c 39 c8 4c 0f 42 d8 4c 89 59 90 01 01 41 32 10 eb 90 01 01 4d 39 d0 0f 95 c0 48 83 c4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}