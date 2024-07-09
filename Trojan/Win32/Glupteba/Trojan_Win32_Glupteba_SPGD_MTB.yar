
rule Trojan_Win32_Glupteba_SPGD_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.SPGD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 e8 89 45 f8 8b 45 dc 01 45 f8 8b 45 f8 33 45 f4 31 45 fc 8b 45 fc 29 45 e8 8b 4d d4 81 c3 ?? ?? ?? ?? 89 5d f0 4e } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}