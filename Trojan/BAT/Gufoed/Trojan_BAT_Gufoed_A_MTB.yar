
rule Trojan_BAT_Gufoed_A_MTB{
	meta:
		description = "Trojan:BAT/Gufoed.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {44 69 73 63 6f 72 64 2e 67 67 2f 73 75 63 6b 67 75 61 72 64 5f } //02 00  Discord.gg/suckguard_
		$a_01_1 = {63 6f 73 74 75 72 61 2e 64 69 73 63 6f 72 64 6d 65 73 73 65 6e 67 65 72 2e 64 6c 6c 2e 63 6f 6d 70 72 65 73 73 65 64 } //02 00  costura.discordmessenger.dll.compressed
		$a_01_2 = {61 6e 74 69 62 6c 61 63 6b 6c 69 73 74 } //02 00  antiblacklist
		$a_01_3 = {61 6e 74 69 63 68 65 63 6b } //00 00  anticheck
	condition:
		any of ($a_*)
 
}