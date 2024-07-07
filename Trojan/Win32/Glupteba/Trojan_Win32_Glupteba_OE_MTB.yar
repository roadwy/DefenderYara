
rule Trojan_Win32_Glupteba_OE_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.OE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b d7 c1 e2 04 03 90 01 01 33 90 02 03 33 90 01 01 2b 90 01 01 81 90 02 09 90 18 8b 90 02 06 29 90 02 03 83 90 02 07 0f 85 90 00 } //1
		$a_02_1 = {8b d7 c1 ea 90 01 01 8d 90 02 02 c7 90 02 09 c7 90 02 09 89 90 02 03 8b 90 02 06 01 90 02 03 8b 90 01 01 c1 90 01 02 03 90 01 01 33 90 02 03 33 90 01 01 2b 90 01 01 81 90 02 09 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}