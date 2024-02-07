
rule Trojan_Win64_CobaltStrike_LK_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.LK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_01_0 = {49 ba 70 2a 57 34 48 1f bc d6 48 8b 4c 24 60 48 8b d6 48 89 4c 24 20 4c 8b c7 48 8b cd 44 8b cb ff 15 } //01 00 
		$a_01_1 = {74 00 61 00 73 00 6b 00 73 00 5c 00 43 00 72 00 65 00 64 00 44 00 75 00 6d 00 70 00 2e 00 72 00 61 00 72 00 } //01 00  tasks\CredDump.rar
		$a_01_2 = {46 55 43 4b } //00 00  FUCK
	condition:
		any of ($a_*)
 
}