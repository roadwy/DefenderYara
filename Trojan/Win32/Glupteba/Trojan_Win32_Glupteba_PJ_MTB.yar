
rule Trojan_Win32_Glupteba_PJ_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.PJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 54 24 10 8b 90 02 03 33 90 01 01 33 90 01 01 8d 90 02 06 89 90 02 03 e8 90 02 04 81 90 02 05 83 90 02 07 0f 85 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}