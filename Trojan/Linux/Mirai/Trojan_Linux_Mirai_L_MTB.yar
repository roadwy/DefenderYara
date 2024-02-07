
rule Trojan_Linux_Mirai_L_MTB{
	meta:
		description = "Trojan:Linux/Mirai.L!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 43 4f 52 4f 4e 41 } //01 00  /bin/busybox CORONA
		$a_00_1 = {50 72 6f 74 65 63 74 69 6e 67 20 79 6f 75 72 20 64 65 76 69 63 65 20 66 72 6f 6d 20 66 75 72 74 68 65 72 20 69 6e 66 65 63 74 69 6f 6e 73 } //01 00  Protecting your device from further infections
		$a_00_2 = {74 30 74 61 6c 63 30 6e 74 72 30 6c 34 } //00 00  t0talc0ntr0l4
	condition:
		any of ($a_*)
 
}