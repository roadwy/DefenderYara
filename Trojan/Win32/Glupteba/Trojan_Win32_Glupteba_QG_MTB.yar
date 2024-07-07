
rule Trojan_Win32_Glupteba_QG_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.QG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {89 55 ec 83 90 02 06 90 18 8b 90 02 02 33 90 02 02 89 90 02 02 8b 90 02 02 33 90 02 02 89 90 02 02 8b 90 02 02 2b 90 02 02 89 90 02 02 8b 90 02 02 50 8d 90 02 02 51 e8 90 02 04 e9 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}