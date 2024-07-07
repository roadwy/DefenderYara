
rule Trojan_Win32_Glupteba_PT_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.PT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 e8 05 89 90 02 02 8b 90 02 02 01 90 02 02 8b 90 02 02 33 90 02 02 89 90 02 02 8b 90 02 02 33 90 02 02 89 90 02 02 8b 90 02 02 2b 90 02 02 89 90 02 02 8b 90 02 02 29 90 02 02 e9 90 02 04 8b 90 02 02 8b 90 02 02 89 90 01 01 8b 90 02 02 8b 90 02 02 89 90 02 02 8b e5 5d c2 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}