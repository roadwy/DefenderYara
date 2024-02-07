
rule Trojan_Win64_GOClipper_DA_MTB{
	meta:
		description = "Trojan:Win64/GOClipper.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 79 6e 61 6d 31 63 20 43 6c 69 70 70 65 72 } //01 00  Dynam1c Clipper
		$a_01_1 = {61 74 6f 74 74 6f 2f 63 6c 69 70 62 6f 61 72 64 2e 57 72 69 74 65 41 6c 6c } //01 00  atotto/clipboard.WriteAll
		$a_01_2 = {61 74 6f 74 74 6f 2f 63 6c 69 70 62 6f 61 72 64 2e 52 65 61 64 41 6c 6c } //01 00  atotto/clipboard.ReadAll
		$a_01_3 = {74 65 6c 65 67 72 61 6d 2d 62 6f 74 2d 61 70 69 2e 4e 65 77 42 6f 74 41 50 49 } //00 00  telegram-bot-api.NewBotAPI
	condition:
		any of ($a_*)
 
}