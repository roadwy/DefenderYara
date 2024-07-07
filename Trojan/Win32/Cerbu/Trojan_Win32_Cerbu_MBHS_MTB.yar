
rule Trojan_Win32_Cerbu_MBHS_MTB{
	meta:
		description = "Trojan:Win32/Cerbu.MBHS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 d2 8a d4 89 15 1c 03 46 01 8b c8 81 e1 ff 00 00 00 89 0d 18 03 46 01 c1 e1 08 03 ca 89 0d 14 03 46 01 c1 e8 10 a3 10 03 46 01 33 f6 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}