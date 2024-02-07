
rule Backdoor_Linux_Mirai_AG_xp{
	meta:
		description = "Backdoor:Linux/Mirai.AG!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 43 4f 52 4f 4e 41 } //01 00  /bin/busybox CORONA
		$a_01_1 = {6e 70 78 58 6f 75 64 69 66 46 65 45 67 47 61 41 43 53 63 73 } //01 00  npxXoudifFeEgGaACScs
		$a_01_2 = {68 6c 4c 6a 7a 74 71 5a } //01 00  hlLjztqZ
		$a_01_3 = {50 72 6f 74 65 63 74 69 6e 67 20 79 6f 75 72 20 64 65 76 69 63 65 20 66 72 6f 6d 20 66 75 72 74 68 65 72 20 69 6e 66 65 63 74 69 6f 6e 73 2e } //00 00  Protecting your device from further infections.
	condition:
		any of ($a_*)
 
}