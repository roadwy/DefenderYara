
rule Trojan_Win32_Glupteba_DM_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.DM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {be d8 85 40 00 b9 56 fe 4b 02 01 ca e8 [0-04] 31 30 40 39 d8 75 e8 } //2
		$a_01_1 = {29 c1 b9 a7 22 ea f9 5f 21 c9 42 48 48 81 fa 6b b1 00 01 75 c8 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}