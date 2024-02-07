
rule Backdoor_Linux_DemonBot_Aa_MTB{
	meta:
		description = "Backdoor:Linux/DemonBot.Aa!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {4d 75 6c 74 69 68 6f 70 20 61 74 74 65 6d 70 74 65 64 } //01 00  Multihop attempted
		$a_00_1 = {62 69 6c 6c 79 62 6f 62 62 6f 74 2e 63 6f 6d 2f 63 72 61 77 6c 65 72 } //02 00  billybobbot.com/crawler
		$a_00_2 = {59 61 6b 75 7a 61 42 6f 74 6e 65 74 } //01 00  YakuzaBotnet
		$a_00_3 = {55 44 50 52 41 57 } //02 00  UDPRAW
		$a_00_4 = {53 65 6c 66 20 52 65 70 20 46 75 63 6b 69 6e 67 20 4e 65 54 69 53 20 61 6e 64 20 54 68 69 73 69 74 79 20 30 6e 20 55 72 20 46 75 43 6b 49 6e 47 20 46 6f 52 65 48 65 41 64 20 57 65 20 42 69 47 20 4c 33 33 54 20 48 61 78 } //00 00  Self Rep Fucking NeTiS and Thisity 0n Ur FuCkInG FoReHeAd We BiG L33T Hax
	condition:
		any of ($a_*)
 
}