
rule Trojan_Win32_Rhadamanthys_MK_MTB{
	meta:
		description = "Trojan:Win32/Rhadamanthys.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e8 90 01 01 03 44 24 90 01 01 03 fe 31 7c 24 90 01 01 c7 05 90 01 08 c7 05 90 01 08 89 44 24 90 01 01 8b 44 24 90 01 01 31 44 24 90 01 01 8b 44 24 90 01 01 29 44 24 90 01 01 8d 44 24 90 01 01 e8 90 01 04 4d 0f 85 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}