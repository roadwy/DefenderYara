
rule Trojan_Win32_Glupteba_EEE_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.EEE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d0 03 f8 d3 e0 c1 ea 05 03 55 dc 57 03 45 d8 89 55 f8 e8 ?? ?? ?? ?? 33 c2 89 45 e8 89 35 d8 ?? 7e 00 8b 45 e8 29 45 f4 81 3d f4 38 f3 00 d5 01 00 00 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}