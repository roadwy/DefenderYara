
rule Trojan_Win32_Neoreblamy_RD_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {d3 f8 33 45 dc 99 89 85 58 ff ff ff 89 95 5c ff ff ff ff b5 5c ff ff ff ff b5 58 ff ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Neoreblamy_RD_MTB_2{
	meta:
		description = "Trojan:Win32/Neoreblamy.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 c0 8b cf 40 d3 e0 85 c2 0f 95 c2 85 c3 0f 95 c0 8a c8 0a c2 22 ca 0f b6 c0 33 d2 84 c9 0f 45 c2 8b 55 fc 03 f6 0f b6 c8 0b f1 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}