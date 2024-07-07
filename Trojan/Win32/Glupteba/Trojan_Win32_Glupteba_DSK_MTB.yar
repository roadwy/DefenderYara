
rule Trojan_Win32_Glupteba_DSK_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.DSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 54 24 16 08 5c 24 14 8a c2 24 fc 33 db c0 e0 04 08 44 24 15 81 3d 90 01 04 38 13 00 00 89 1d 90 01 04 75 90 00 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}