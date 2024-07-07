
rule Trojan_Win32_Glupteba_OQ_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.OQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b d7 c1 ea 05 c7 05 90 02 08 c7 05 90 02 08 89 90 02 03 8b 90 02 06 01 90 02 03 8b 90 02 03 33 90 01 01 33 90 01 01 8d 90 02 06 e8 90 02 04 8b 90 02 06 29 90 02 03 83 90 02 07 0f 85 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}