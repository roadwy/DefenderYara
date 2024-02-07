
rule Trojan_BAT_Xmrig_NEAD_MTB{
	meta:
		description = "Trojan:BAT/Xmrig.NEAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {16 0a 2b 3a 00 28 12 00 00 0a 72 25 00 00 70 28 09 00 00 06 6f 13 00 00 0a 28 14 00 00 0a 0b 07 16 07 8e 69 28 15 00 00 0a 07 0c de 17 26 } //05 00 
		$a_01_1 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 74 00 74 00 61 00 63 00 68 00 6d 00 65 00 6e 00 74 00 73 00 } //00 00  https://cdn.discordapp.com/attachments
	condition:
		any of ($a_*)
 
}