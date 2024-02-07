
rule Trojan_Win64_Dridex_SC_MSR{
	meta:
		description = "Trojan:Win64/Dridex.SC!MSR,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {6c 69 66 65 68 61 63 6b } //01 00  lifehack
		$a_01_1 = {69 6d 70 6f 72 74 61 6e 74 68 65 6e 74 61 69 } //01 00  importanthentai
		$a_01_2 = {6c 6f 76 65 72 65 6d 6f 76 65 64 } //01 00  loveremoved
		$a_01_3 = {53 71 75 69 72 72 65 6c 46 69 73 68 43 68 72 6f 6d 65 73 63 72 69 70 74 } //01 00  SquirrelFishChromescript
		$a_01_4 = {53 00 61 00 6e 00 64 00 62 00 6f 00 78 00 } //01 00  Sandbox
		$a_01_5 = {33 37 74 6f 47 4f 67 37 38 69 6e 73 63 6f 72 65 73 71 62 75 62 62 61 } //00 00  37toGOg78inscoresqbubba
	condition:
		any of ($a_*)
 
}