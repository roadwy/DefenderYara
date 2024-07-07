
rule Trojan_Linux_ZHTrap_A_xp{
	meta:
		description = "Trojan:Linux/ZHTrap.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_00_0 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 5a 48 54 52 41 50 } //1 /bin/busybox ZHTRAP
		$a_00_1 = {5a 6f 6e 65 53 65 63 } //1 ZoneSec
		$a_00_2 = {51 6a 66 6a 78 53 52 44 46 47 53 46 44 64 66 } //1 QjfjxSRDFGSFDdf
		$a_00_3 = {74 30 74 61 6c 63 30 6e 74 72 30 6c 34 } //1 t0talc0ntr0l4
		$a_00_4 = {68 61 63 6b 74 68 65 77 6f 72 6c 64 31 33 33 37 } //1 hacktheworld1337
		$a_00_5 = {b0 80 9f e5 98 31 82 e0 a2 23 a0 e1 02 34 a0 e1 03 30 62 e0 01 10 63 e0 01 10 20 e0 0c 30 8e e0 01 c0 8c e2 01 30 23 e0 0a 00 5c e1 06 30 c4 e7 01 50 87 e2 00 e0 a0 e3 0c 40 a0 e1 0f 00 00 0a 6c 10 9f e5 00 20 91 e5 02 00 d7 e7 98 20 83 e0 a3 33 a0 e1 03 24 a0 e1 06 10 d4 e7 02 20 63 e0 00 00 62 e0 00 10 21 e0 ff 00 01 e2 0e 00 55 e3 06 00 c4 e7 0e 70 a0 e1 df ff ff ca } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=4
 
}