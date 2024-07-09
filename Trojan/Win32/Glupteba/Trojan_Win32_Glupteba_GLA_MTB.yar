
rule Trojan_Win32_Glupteba_GLA_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.GLA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 d0 89 45 fc 89 55 f0 8b 45 f0 83 45 f8 ?? 29 45 f8 83 6d f8 } //1
		$a_03_1 = {d3 e8 03 45 dc 8b c8 8b 45 f0 31 45 fc 31 4d fc 2b 7d fc 81 c6 ?? ?? ?? ?? ff 4d e4 89 7d ?? 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}