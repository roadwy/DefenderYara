
rule Trojan_Win32_Glupteba_PV_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.PV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 55 e4 33 90 02 02 89 90 02 02 8b 90 02 02 33 90 02 02 89 90 02 02 8b 90 02 02 2b 90 02 02 89 90 02 02 8b 90 02 02 2b 90 02 02 89 90 02 02 e9 90 02 04 8b 90 02 02 8b 90 02 02 89 08 8b 90 02 02 8b 90 02 02 89 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}