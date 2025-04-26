
rule Trojan_Linux_SunOSRKT_A_xp{
	meta:
		description = "Trojan:Linux/SunOSRKT.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_00_0 = {6c 73 6f 66 5f 66 69 6c 74 65 72 73 } //1 lsof_filters
		$a_00_1 = {2f 75 73 72 2f 6c 69 62 2f 6c 69 62 58 2e 61 2f 75 63 6f 6e 66 2e 69 6e 76 } //1 /usr/lib/libX.a/uconf.inv
		$a_00_2 = {2f 75 73 72 2f 6c 69 62 2f 6c 69 62 58 2e 61 2f 62 69 6e 2f } //1 /usr/lib/libX.a/bin/
		$a_00_3 = {9d e3 bc 90 11 00 00 86 13 00 00 86 15 00 00 86 d0 02 23 28 d2 02 63 60 40 00 00 73 d4 02 a3 6c b0 92 20 00 22 80 00 08 11 00 00 46 } //1
		$a_00_4 = {40 00 41 98 90 07 bd f0 11 00 00 86 13 00 00 86 15 00 00 86 d0 02 23 28 d2 02 63 60 40 00 00 52 d4 02 a3 74 92 92 20 00 12 80 00 04 b0 07 bc f0 11 00 00 46 92 12 20 78 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=3
 
}