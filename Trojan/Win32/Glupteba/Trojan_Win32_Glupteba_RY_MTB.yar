
rule Trojan_Win32_Glupteba_RY_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.RY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 ea 05 8d 0c 18 c7 05 90 01 04 84 10 d6 cb c7 05 90 01 04 ff ff ff ff 89 54 24 90 01 01 8b 84 24 90 01 04 01 44 24 90 01 01 8b c3 c1 e0 04 03 84 24 90 01 04 33 44 24 90 01 01 33 c1 2b f8 81 3d 90 01 04 17 04 00 00 75 90 00 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}