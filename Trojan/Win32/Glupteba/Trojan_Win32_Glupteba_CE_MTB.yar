
rule Trojan_Win32_Glupteba_CE_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.CE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 39 81 c3 [0-04] 81 c6 [0-04] 81 c1 04 00 00 00 09 de 81 ee [0-04] 39 d1 75 db } //2
		$a_01_1 = {31 30 89 ca 29 d1 81 c0 04 00 00 00 4a 29 da 39 f8 75 e8 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=2
 
}