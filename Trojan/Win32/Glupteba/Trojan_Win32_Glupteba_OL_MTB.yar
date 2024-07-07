
rule Trojan_Win32_Glupteba_OL_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.OL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 ea 05 c7 05 90 02 08 c7 05 90 02 08 89 90 02 03 8b 90 02 03 01 90 02 03 8b 90 02 07 33 90 01 01 33 90 02 03 68 90 02 04 8d 90 02 03 51 2b 90 01 01 e8 90 02 04 83 90 02 04 0f 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}