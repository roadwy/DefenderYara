
rule Trojan_Win32_Glupteba_OD_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.OD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b d3 c1 ea 05 8d 90 02 03 c7 05 90 02 08 c7 05 90 02 08 89 90 02 03 8b 90 02 06 01 90 02 05 c1 90 02 05 33 90 02 03 33 90 02 03 81 90 02 09 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}