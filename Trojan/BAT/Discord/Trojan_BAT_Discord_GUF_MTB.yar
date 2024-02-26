
rule Trojan_BAT_Discord_GUF_MTB{
	meta:
		description = "Trojan:BAT/Discord.GUF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_80_0 = {74 68 65 74 61 73 74 6c 72 2d 64 65 66 61 75 6c 74 2d 72 74 64 62 2e 66 69 72 65 62 61 73 65 69 6f 2e 63 6f 6d } //thetastlr-default-rtdb.firebaseio.com  01 00 
		$a_80_1 = {61 6c 31 68 69 4b 68 65 67 65 72 35 30 4e 65 6e 68 4b 50 7a 59 69 79 67 47 5a 47 6c 73 6a 6d 48 4d 43 77 52 59 65 6c 74 } //al1hiKheger50NenhKPzYiygGZGlsjmHMCwRYelt  01 00 
		$a_80_2 = {63 68 65 63 6b 69 70 2e 64 79 6e 64 6e 73 2e 6f 72 67 } //checkip.dyndns.org  01 00 
		$a_01_3 = {74 68 65 74 61 73 74 65 61 6c 65 72 } //01 00  thetastealer
		$a_01_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_5 = {5c 52 65 6c 65 61 73 65 5c 74 68 65 74 61 73 74 65 61 6c 65 72 2e 70 64 62 } //00 00  \Release\thetastealer.pdb
	condition:
		any of ($a_*)
 
}