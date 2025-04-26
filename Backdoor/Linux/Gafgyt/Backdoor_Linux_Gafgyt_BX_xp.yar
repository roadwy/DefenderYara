
rule Backdoor_Linux_Gafgyt_BX_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.BX!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {46 4e 2d 4c 41 47 } //1 FN-LAG
		$a_01_1 = {4c 49 47 48 54 53 2d 4f 55 54 } //1 LIGHTS-OUT
		$a_01_2 = {68 6c 4c 6a 7a 74 71 5a } //1 hlLjztqZ
		$a_01_3 = {6e 70 78 58 6f 75 64 69 66 46 65 45 67 47 61 41 43 53 63 73 } //1 npxXoudifFeEgGaACScs
		$a_01_4 = {4f 56 48 2d 4b 49 4c 4c 45 52 } //1 OVH-KILLER
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}