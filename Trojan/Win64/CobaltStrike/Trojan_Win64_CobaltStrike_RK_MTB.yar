
rule Trojan_Win64_CobaltStrike_RK_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.RK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {47 6f 20 62 75 69 6c 64 20 49 44 3a } //01 00  Go build ID:
		$a_01_1 = {30 63 6f 62 61 6c 74 73 74 72 69 6b 65 2d 63 68 74 73 65 63 } //00 00  0cobaltstrike-chtsec
	condition:
		any of ($a_*)
 
}