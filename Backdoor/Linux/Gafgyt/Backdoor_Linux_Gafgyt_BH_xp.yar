
rule Backdoor_Linux_Gafgyt_BH_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.BH!xp,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {63 75 72 6c 20 2d 4f 20 68 74 74 70 3a 2f 2f 90 02 20 2f 73 68 61 6b 65 72 90 00 } //01 00 
		$a_01_1 = {68 69 73 74 6f 72 79 20 2d 63 } //01 00  history -c
		$a_01_2 = {72 6d 20 2d 72 66 20 73 68 61 6b 65 72 } //01 00  rm -rf shaker
		$a_01_3 = {63 68 6d 6f 64 20 2b 78 20 73 68 61 6b 65 72 } //01 00  chmod +x shaker
		$a_01_4 = {6e 70 78 58 6f 75 64 69 66 46 65 45 67 47 61 41 43 53 63 73 } //01 00  npxXoudifFeEgGaACScs
		$a_01_5 = {68 6c 4c 6a 7a 74 71 5a } //00 00  hlLjztqZ
	condition:
		any of ($a_*)
 
}