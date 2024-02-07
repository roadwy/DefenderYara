
rule Trojan_BAT_Disco_RE_MTB{
	meta:
		description = "Trojan:BAT/Disco.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_01_0 = {0a 2b 14 00 11 04 17 58 13 04 11 04 09 8e 69 fe 04 13 05 11 05 2d 97 06 0c 2b 00 08 2a } //01 00 
		$a_01_1 = {73 00 75 00 70 00 65 00 72 00 73 00 65 00 78 00 2e 00 65 00 78 00 65 00 } //01 00  supersex.exe
		$a_01_2 = {53 65 6e 64 4d 65 73 73 61 67 65 54 6f 44 69 73 63 6f 72 64 } //00 00  SendMessageToDiscord
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Disco_RE_MTB_2{
	meta:
		description = "Trojan:BAT/Disco.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 05 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 70 00 69 00 2f 00 77 00 65 00 62 00 68 00 6f 00 6f 00 6b 00 73 00 2f 00 31 00 30 00 36 00 33 00 33 00 35 00 38 00 33 00 33 00 30 00 31 00 30 00 33 00 34 00 30 00 32 00 35 00 30 00 36 00 2f 00 6a 00 5f 00 61 00 41 00 66 00 44 00 71 00 4c 00 67 00 65 00 4d 00 67 00 5a 00 4e 00 46 00 61 00 4f 00 64 00 59 00 77 00 31 00 65 00 38 00 34 00 77 00 67 00 32 00 } //02 00  https://discord.com/api/webhooks/1063358330103402506/j_aAfDqLgeMgZNFaOdYw1e84wg2
		$a_01_1 = {74 65 73 74 69 6e 67 5f 77 65 62 2e 70 64 62 } //02 00  testing_web.pdb
		$a_01_2 = {24 31 32 36 35 33 30 39 61 2d 33 38 30 36 2d 34 61 32 39 2d 38 32 63 66 2d 32 39 34 62 33 66 32 37 31 31 65 35 } //01 00  $1265309a-3806-4a29-82cf-294b3f2711e5
		$a_01_3 = {74 61 6b 65 5f 73 63 72 65 65 6e 73 68 6f 74 } //00 00  take_screenshot
	condition:
		any of ($a_*)
 
}