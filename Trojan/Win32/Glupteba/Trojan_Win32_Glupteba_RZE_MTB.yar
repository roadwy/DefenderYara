
rule Trojan_Win32_Glupteba_RZE_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.RZE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c3 d3 e8 89 45 f8 8b 45 d4 01 45 f8 8b 45 f8 33 45 e4 31 45 fc 8b 45 fc 29 45 ec 8b 4d d0 81 c7 ?? ?? ?? ?? 89 7d f0 4e 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}