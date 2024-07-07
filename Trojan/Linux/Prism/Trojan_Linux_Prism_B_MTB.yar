
rule Trojan_Linux_Prism_B_MTB{
	meta:
		description = "Trojan:Linux/Prism.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 45 ec 48 98 48 c1 e0 03 48 03 45 d0 48 8b 00 48 89 c7 e8 90 01 04 48 89 c2 8b 45 ec 48 98 48 c1 e0 03 48 03 45 d0 48 8b 00 be 20 00 00 00 48 89 c7 e8 90 01 04 83 45 ec 01 8b 45 ec 3b 45 dc 7c bc e8 90 01 04 85 c0 90 00 } //1
		$a_02_1 = {bf 00 00 00 00 e8 90 01 04 e8 90 01 04 85 c0 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}