
rule Trojan_Win32_Glupteba_PW_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.PW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 45 f8 83 90 02 02 89 90 02 02 8b 90 02 02 3b 90 02 02 73 90 01 01 83 90 02 06 90 18 8b 90 02 02 89 90 02 02 81 90 02 09 90 18 8b 90 02 02 d1 90 01 01 89 90 02 02 81 90 02 09 90 18 8b 90 02 02 51 8b 90 02 02 8b 90 02 02 8d 90 02 02 51 e8 90 02 04 eb 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}