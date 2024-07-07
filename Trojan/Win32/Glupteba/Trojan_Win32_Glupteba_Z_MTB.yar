
rule Trojan_Win32_Glupteba_Z_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.Z!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 54 24 14 8b 4c 24 90 01 01 30 04 0a 83 bc 90 00 } //2
		$a_03_1 = {41 89 4c 24 90 01 01 3b 8c 90 00 } //2
		$a_03_2 = {8a 14 31 a1 90 01 04 88 14 30 90 00 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2) >=6
 
}