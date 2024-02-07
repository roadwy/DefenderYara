
rule Trojan_Linux_Mirai_SD_xp{
	meta:
		description = "Trojan:Linux/Mirai.SD!xp,SIGNATURE_TYPE_ELFHSTR_EXT,08 00 08 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {55 24 65 53 3a 44 5a 43 6a 45 6d 59 78 57 70 74 } //02 00  U$eS:DZCjEmYxWpt
		$a_01_1 = {7a 37 75 4e 42 63 33 20 61 32 4c 54 } //02 00  z7uNBc3 a2LT
		$a_01_2 = {34 51 30 79 58 6c 67 41 4b 50 36 69 31 56 72 4f } //02 00  4Q0yXlgAKP6i1VrO
		$a_01_3 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 } //00 00  /bin/busybox
	condition:
		any of ($a_*)
 
}