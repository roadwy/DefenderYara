
rule Trojan_Win32_SmokeLoader_DF_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.DF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 d8 03 45 b0 03 45 e8 89 45 b4 6a 00 e8 90 01 04 8b d8 03 5d b4 6a 00 e8 90 01 04 2b d8 8b 45 ec 31 18 83 45 e8 04 83 45 ec 04 8b 45 e8 3b 45 e4 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_SmokeLoader_DF_MTB_2{
	meta:
		description = "Trojan:Win32/SmokeLoader.DF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 00 6f 00 77 00 6f 00 70 00 75 00 6b 00 65 00 78 00 6f 00 72 00 65 00 68 00 6f 00 62 00 65 00 6a 00 69 00 72 00 69 00 72 00 61 00 77 00 75 00 70 00 65 00 6e 00 75 00 20 00 73 00 65 00 73 00 61 00 72 00 65 00 7a 00 6f 00 70 00 6f 00 63 00 6f 00 76 00 61 00 76 00 69 00 67 00 6f 00 77 00 75 00 77 00 61 00 66 00 65 00 79 00 65 00 79 00 } //01 00  fowopukexorehobejirirawupenu sesarezopocovavigowuwafeyey
		$a_01_1 = {6e 00 61 00 6b 00 6f 00 62 00 65 00 70 00 65 00 70 00 75 00 77 00 69 00 73 00 6f 00 6a 00 6f 00 66 00 75 00 6a 00 61 00 6c 00 65 00 78 00 65 00 } //01 00  nakobepepuwisojofujalexe
		$a_01_2 = {76 00 75 00 6a 00 6f 00 6e 00 69 00 79 00 61 00 79 00 65 00 74 00 69 00 6b 00 6f 00 77 00 65 00 7a 00 61 00 77 00 69 00 72 00 75 00 20 00 6b 00 69 00 68 00 6f 00 6a 00 65 00 63 00 61 00 67 00 6f 00 6a 00 75 00 68 00 6f 00 73 00 61 00 6a 00 61 00 6e 00 69 00 72 00 6f 00 73 00 75 00 } //01 00  vujoniyayetikowezawiru kihojecagojuhosajanirosu
		$a_01_3 = {67 00 69 00 6a 00 6f 00 63 00 75 00 6a 00 75 00 76 00 65 00 70 00 6f 00 20 00 6e 00 65 00 6e 00 6f 00 70 00 75 00 66 00 65 00 6c 00 61 00 73 00 61 00 77 00 69 00 6d 00 75 00 77 00 69 00 73 00 75 00 77 00 65 00 62 00 6f 00 78 00 } //01 00  gijocujuvepo nenopufelasawimuwisuwebox
		$a_01_4 = {6e 69 6b 65 77 61 73 65 63 69 74 69 67 6f 66 61 72 69 63 6f 78 65 6d 75 73 69 70 65 77 69 70 20 67 75 6d 69 70 69 74 69 66 69 72 69 6b 6f 78 61 6e 69 73 61 62 61 67 69 } //01 00  nikewasecitigofaricoxemusipewip gumipitifirikoxanisabagi
		$a_01_5 = {64 75 72 65 72 61 63 6f 62 61 6e 6f 6b 69 74 75 77 75 20 74 75 77 65 68 61 6a 61 70 75 67 20 6a 75 6a 61 78 61 7a 75 62 75 77 65 63 65 73 65 74 20 70 65 74 65 63 69 66 6f 64 75 76 69 6b 69 6c 61 62 6f 6e 6f 72 61 6c 65 7a 6f 62 75 } //00 00  dureracobanokituwu tuwehajapug jujaxazubuweceset petecifoduvikilabonoralezobu
	condition:
		any of ($a_*)
 
}