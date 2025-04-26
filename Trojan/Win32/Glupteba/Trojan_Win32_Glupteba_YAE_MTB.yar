
rule Trojan_Win32_Glupteba_YAE_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.YAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 e0 01 45 fc 8b 45 f8 8b 4d f0 8d 14 01 8b 4d f4 31 55 fc ff 75 fc d3 e8 03 c3 50 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}