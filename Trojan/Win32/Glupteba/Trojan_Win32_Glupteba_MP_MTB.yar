
rule Trojan_Win32_Glupteba_MP_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.MP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {33 44 24 10 c7 05 90 02 08 8b c8 89 90 02 03 8d 90 02 06 e8 90 02 04 81 3d 90 02 08 75 90 00 } //1
		$a_02_1 = {5f 89 70 04 5e 5d 89 10 5b 90 02 06 c2 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}