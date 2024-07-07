
rule Trojan_Linux_BForce_A_xp{
	meta:
		description = "Trojan:Linux/BForce.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {00 f0 ae 1c 00 f0 3e 21 08 f0 3e 21 08 34 40 } //1
		$a_00_1 = {04 af 1c 00 04 3f 21 08 04 3f 21 08 f8 } //1
		$a_00_2 = {f0 ae 1c 00 f0 3e 21 08 f0 3e 21 08 } //1
		$a_00_3 = {83 c4 10 85 c0 89 c3 75 63 83 ec 08 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}