
rule Trojan_Win32_Glupteba_AMMA_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.AMMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {81 ec 08 08 00 00 a1 90 01 04 33 c4 89 84 24 04 08 00 00 a1 90 01 04 69 c0 fd 43 03 00 81 3d 90 01 04 9e 13 00 00 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}