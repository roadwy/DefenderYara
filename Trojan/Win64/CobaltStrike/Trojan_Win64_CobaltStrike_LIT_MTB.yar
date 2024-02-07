
rule Trojan_Win64_CobaltStrike_LIT_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.LIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {99 41 f7 f9 48 8d 05 90 01 04 48 63 d2 8a 0c 10 90 01 01 8b 44 24 48 42 32 0c 00 42 88 0c 06 49 ff c0 eb 90 00 } //01 00 
		$a_01_1 = {43 68 65 63 6b 4d 65 6e 75 52 61 64 69 6f } //00 00  CheckMenuRadio
	condition:
		any of ($a_*)
 
}