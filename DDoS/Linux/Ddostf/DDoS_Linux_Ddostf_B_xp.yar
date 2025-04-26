
rule DDoS_Linux_Ddostf_B_xp{
	meta:
		description = "DDoS:Linux/Ddostf.B!xp,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {c7 44 24 08 06 00 00 00 c7 44 24 04 01 00 00 00 c7 04 24 02 00 00 00 89 44 24 20 e8 ?? ?? ?? 00 c7 44 24 08 10 00 00 00 89 c3 8d 44 24 1c 89 44 24 04 89 1c 24 e8 ?? ?? ?? 00 83 f8 ff } //1
		$a_00_1 = {89 f6 8d bc 27 00 00 00 00 80 3d e0 fa 0f 08 00 75 65 55 89 e5 53 bb 28 f0 0f 08 83 ec 14 a1 e4 fa 0f 08 81 eb 20 f0 0f 08 c1 fb 02 83 eb 01 39 d8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}