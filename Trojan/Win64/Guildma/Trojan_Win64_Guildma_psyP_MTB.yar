
rule Trojan_Win64_Guildma_psyP_MTB{
	meta:
		description = "Trojan:Win64/Guildma.psyP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 07 00 "
		
	strings :
		$a_01_0 = {41 51 41 50 52 48 31 d2 65 48 8b 52 60 51 48 8b 52 18 56 48 8b 52 20 48 8b 72 50 4d 31 c9 48 0f b7 4a 4a 48 31 c0 ac 3c 61 7c 02 2c 20 41 c1 c9 0d 41 01 c1 e2 ed 52 41 51 } //00 00 
	condition:
		any of ($a_*)
 
}