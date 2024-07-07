
rule Trojan_Win32_Zusy_DIW_MTB{
	meta:
		description = "Trojan:Win32/Zusy.DIW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d0 c1 ea 05 03 d5 8b c8 c1 e1 04 89 54 24 1c 03 cb 8d 14 06 33 ca 89 4c 24 10 89 3d 90 01 04 8b 44 24 1c 01 05 a4 87 7b 00 a1 90 01 04 89 44 24 34 89 7c 24 1c 8b 44 24 34 01 44 24 1c 8b 44 24 10 33 44 24 1c 89 44 24 1c 8b 4c 24 1c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}