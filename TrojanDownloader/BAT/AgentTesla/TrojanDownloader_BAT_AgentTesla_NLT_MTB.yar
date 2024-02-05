
rule TrojanDownloader_BAT_AgentTesla_NLT_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.NLT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,33 00 33 00 07 00 00 0a 00 "
		
	strings :
		$a_01_0 = {28 16 00 00 0a 72 01 00 00 70 17 8d 14 00 00 01 25 16 d0 23 00 00 01 28 16 00 00 0a a2 28 17 00 00 0a 14 17 8d 11 00 00 01 25 16 20 10 27 00 00 8c 23 00 00 01 a2 6f 18 } //0a 00 
		$a_80_1 = {69 6e 66 69 6e 69 74 79 2d 63 68 65 61 74 73 2e 6f 72 67 2f } //infinity-cheats.org/  0a 00 
		$a_01_2 = {47 65 74 4d 65 74 68 6f 64 73 } //0a 00 
		$a_01_3 = {54 6f 49 6e 74 33 32 } //0a 00 
		$a_01_4 = {48 65 6c 70 65 72 } //01 00 
		$a_80_5 = {4c 68 77 61 67 68 73 79 72 63 65 74 73 79 6c 74 2e 4b 69 77 6c 75 6c 63 70 6d 6d 73 68 68 } //Lhwaghsyrcetsylt.Kiwlulcpmmshh  01 00 
		$a_80_6 = {53 75 79 65 68 64 6d 66 6a 61 79 72 2e 41 74 63 65 7a 63 6f 71 61 } //Suyehdmfjayr.Atcezcoqa  00 00 
	condition:
		any of ($a_*)
 
}