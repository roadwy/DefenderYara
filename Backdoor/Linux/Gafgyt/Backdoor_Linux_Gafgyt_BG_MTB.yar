
rule Backdoor_Linux_Gafgyt_BG_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.BG!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 65 6c 66 20 72 65 70 20 6e 65 74 69 73 20 61 6e 64 20 6e 72 70 65 20 67 6f 74 20 62 69 67 20 64 69 63 6b 73 20 6c 6f 6c } //01 00  self rep netis and nrpe got big dicks lol
		$a_00_1 = {2f 65 74 63 2f 78 69 6e 65 74 2e 64 2f } //01 00  /etc/xinet.d/
		$a_00_2 = {54 53 6f 75 72 63 65 20 45 6e 67 69 6e 65 20 51 75 65 72 79 } //01 00  TSource Engine Query
		$a_00_3 = {6e 70 78 58 6f 75 64 69 66 46 65 45 67 47 61 41 43 53 63 73 } //01 00  npxXoudifFeEgGaACScs
		$a_00_4 = {33 31 6d 42 6f 61 74 6e 65 74 } //01 00  31mBoatnet
		$a_00_5 = {68 6c 4c 6a 7a 74 71 5a } //00 00  hlLjztqZ
	condition:
		any of ($a_*)
 
}