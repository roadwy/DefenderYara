
rule Trojan_Linux_Mirai_SD_xp{
	meta:
		description = "Trojan:Linux/Mirai.SD!xp,SIGNATURE_TYPE_ELFHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {55 24 65 53 3a 44 5a 43 6a 45 6d 59 78 57 70 74 } //2 U$eS:DZCjEmYxWpt
		$a_01_1 = {7a 37 75 4e 42 63 33 20 61 32 4c 54 } //2 z7uNBc3 a2LT
		$a_01_2 = {34 51 30 79 58 6c 67 41 4b 50 36 69 31 56 72 4f } //2 4Q0yXlgAKP6i1VrO
		$a_01_3 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 } //2 /bin/busybox
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}