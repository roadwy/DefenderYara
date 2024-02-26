
rule Trojan_Win32_Zenpak_MBKB_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.MBKB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {69 79 6c 61 68 74 65 38 37 2e 64 6c 6c 00 42 6f 64 73 75 77 74 75 62 65 73 74 64 48 6e 69 74 00 6b 65 72 6e 65 6c 33 32 2e 53 6c 65 65 70 } //01 00  祩慬瑨㡥⸷汤l潂獤睵畴敢瑳䡤楮t敫湲汥㈳匮敬灥
		$a_01_1 = {7a 3a 5c 76 45 41 69 5c 6a 31 4b 73 57 70 2e 70 64 62 } //00 00  z:\vEAi\j1KsWp.pdb
	condition:
		any of ($a_*)
 
}