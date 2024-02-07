
rule Trojan_BAT_AgentTesla_RPO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RPO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 } //01 00  cdn.discordapp.com
		$a_01_1 = {50 00 70 00 63 00 6d 00 68 00 78 00 2e 00 70 00 6e 00 67 00 } //01 00  Ppcmhx.png
		$a_01_2 = {46 00 6f 00 68 00 61 00 61 00 73 00 67 00 63 00 7a 00 6b 00 73 00 62 00 63 00 67 00 6f 00 78 00 72 00 76 00 76 00 64 00 78 00 6d 00 } //01 00  Fohaasgczksbcgoxrvvdxm
		$a_01_3 = {52 00 6f 00 65 00 75 00 61 00 74 00 78 00 72 00 6b 00 6a 00 79 00 66 00 6a 00 6d 00 6d 00 63 00 69 00 72 00 68 00 74 00 } //01 00  Roeuatxrkjyfjmmcirht
		$a_01_4 = {49 00 77 00 78 00 74 00 74 00 72 00 6c 00 6c 00 61 00 69 00 64 00 76 00 62 00 6a 00 76 00 65 00 71 00 } //01 00  Iwxttrllaidvbjveq
		$a_01_5 = {45 00 6d 00 61 00 69 00 6c 00 20 00 43 00 68 00 65 00 63 00 6b 00 65 00 72 00 20 00 50 00 72 00 6f 00 } //00 00  Email Checker Pro
	condition:
		any of ($a_*)
 
}