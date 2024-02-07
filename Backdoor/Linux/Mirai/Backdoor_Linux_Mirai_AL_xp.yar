
rule Backdoor_Linux_Mirai_AL_xp{
	meta:
		description = "Backdoor:Linux/Mirai.AL!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 75 73 72 2f 73 62 69 6e 2f 64 72 6f 70 62 65 61 72 } //01 00  /usr/sbin/dropbear
		$a_00_1 = {62 66 61 65 38 68 66 62 75 34 69 77 68 72 66 34 69 75 6c 77 62 72 69 75 6c 71 34 77 } //01 00  bfae8hfbu4iwhrf4iulwbriulq4w
		$a_00_2 = {5b 6b 69 6c 6c 65 72 5d 20 66 69 6e 69 73 68 65 64 } //01 00  [killer] finished
		$a_00_3 = {6e 70 78 58 6f 75 64 69 66 46 65 45 67 47 61 41 43 53 63 73 } //01 00  npxXoudifFeEgGaACScs
		$a_00_4 = {6c 4c 6a 7a 74 71 5a } //00 00  lLjztqZ
	condition:
		any of ($a_*)
 
}