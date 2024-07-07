
rule Trojan_Win32_Glupteba_OY_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.OY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {83 c7 08 83 6c 24 10 01 90 18 81 3d 90 02 08 90 18 81 3d 90 02 08 90 18 57 e8 90 02 04 81 3d 90 02 08 75 0a 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}