
rule Trojan_Win32_Glupteba_MN_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.MN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b cf c1 e9 05 89 90 02 03 8b 90 02 0a 01 44 24 10 8b f7 c1 e6 04 03 b4 24 90 02 04 8d 90 02 03 33 f2 81 3d 90 02 08 c7 05 90 02 08 90 18 31 90 02 04 81 90 02 09 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}