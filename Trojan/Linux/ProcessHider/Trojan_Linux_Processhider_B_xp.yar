
rule Trojan_Linux_Processhider_B_xp{
	meta:
		description = "Trojan:Linux/Processhider.B!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {ec 08 48 8b 05 1d 17 20 00 48 85 c0 74 05 e8 ab 00 00 00 } //1
		$a_00_1 = {48 83 3d 68 13 20 00 00 74 26 48 8b 05 4f 15 20 00 48 85 c0 74 1a } //1
		$a_00_2 = {48 89 75 a0 48 89 55 98 48 8b 45 a8 48 89 c7 e8 7b fe ff ff } //1
		$a_00_3 = {48 89 c7 e8 30 fd ff ff 48 85 c0 75 13 48 8b 45 e8 48 89 c7 e8 df fc ff ff } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}