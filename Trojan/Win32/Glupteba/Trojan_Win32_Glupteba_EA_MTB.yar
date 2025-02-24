
rule Trojan_Win32_Glupteba_EA_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.EA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4d f0 8b 45 f4 8b d3 d3 ea 03 c3 03 55 d8 33 d0 31 55 f8 2b 7d f8 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_Win32_Glupteba_EA_MTB_2{
	meta:
		description = "Trojan:Win32/Glupteba.EA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d7 33 d6 c7 05 ?? ?? ?? ?? ff ff ff ff 2b da 8b 44 24 1c 29 44 24 10 83 6c 24 14 01 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}