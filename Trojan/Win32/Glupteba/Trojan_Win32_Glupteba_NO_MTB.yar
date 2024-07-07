
rule Trojan_Win32_Glupteba_NO_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.NO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b c6 c1 e8 05 89 90 02 03 8d 90 02 03 e8 90 02 04 8d 90 02 03 8b 90 02 03 e8 90 02 04 81 3d 90 02 08 8b 90 02 03 90 18 90 02 0a 33 90 02 03 83 90 02 06 89 90 02 03 8b 90 02 03 29 90 02 03 81 90 02 06 ff 90 02 06 0f 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}