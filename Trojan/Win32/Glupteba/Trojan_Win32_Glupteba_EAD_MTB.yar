
rule Trojan_Win32_Glupteba_EAD_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.EAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 55 e0 8b 45 fc 8b f3 c1 ee 05 03 75 e8 03 fa 03 c3 33 f8 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}