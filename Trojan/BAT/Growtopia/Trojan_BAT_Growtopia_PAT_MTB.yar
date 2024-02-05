
rule Trojan_BAT_Growtopia_PAT_MTB{
	meta:
		description = "Trojan:BAT/Growtopia.PAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_80_0 = {47 72 6f 77 74 6f 70 69 61 2d 46 75 6c 6c 2d 46 75 64 2d 53 74 65 61 6c 65 72 2d 6d 61 73 74 65 72 5c 6f 62 6a 5c 44 65 62 75 67 5c 46 75 64 2e 70 64 62 } //Growtopia-Full-Fud-Stealer-master\obj\Debug\Fud.pdb  01 00 
		$a_80_1 = {64 69 73 63 6f 72 64 2e 63 6f 6d 2f 61 70 69 2f 77 65 62 68 6f 6f 6b 73 2f 31 30 30 37 32 38 35 38 31 30 34 36 38 35 30 37 36 35 38 2f 67 34 71 35 4d 70 } //discord.com/api/webhooks/1007285810468507658/g4q5Mp  00 00 
	condition:
		any of ($a_*)
 
}