
rule Ransom_Win32_Conti_AC_MTB{
	meta:
		description = "Ransom:Win32/Conti.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 06 c0 e0 90 01 01 0a c8 c0 e1 90 01 01 8a 46 90 01 01 24 90 01 01 0a c8 88 0c 90 01 01 42 8d 76 90 01 01 81 fa 90 01 04 7d 90 01 01 8b 90 0a 30 00 8a 4e 90 01 01 80 e1 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}