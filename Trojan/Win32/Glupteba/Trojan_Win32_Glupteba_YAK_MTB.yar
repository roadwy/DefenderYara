
rule Trojan_Win32_Glupteba_YAK_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.YAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 55 f4 33 db 8b 45 f8 33 d1 03 45 e4 8b 0d 90 01 04 33 c2 c7 05 90 01 08 89 55 f4 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}