
rule Trojan_Win32_Glupteba_OW_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.OW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b f5 c1 e6 04 81 3d 90 02 08 90 18 03 90 02 06 81 90 02 0d 90 18 8b 90 01 01 c1 90 02 02 c7 05 90 02 08 c7 05 90 02 08 89 90 02 03 8b 90 02 06 01 90 02 03 81 3d 90 02 08 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}