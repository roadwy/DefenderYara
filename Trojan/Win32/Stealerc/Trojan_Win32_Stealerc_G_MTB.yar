
rule Trojan_Win32_Stealerc_G_MTB{
	meta:
		description = "Trojan:Win32/Stealerc.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 45 f0 8b 45 f0 89 45 ec 8b 55 f8 8b 4d f4 8b c2 d3 e8 8b 4d fc 81 c7 ?? ?? ?? ?? 89 7d e8 03 45 d0 33 45 ec 33 c8 2b f1 83 eb 01 89 4d fc 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}