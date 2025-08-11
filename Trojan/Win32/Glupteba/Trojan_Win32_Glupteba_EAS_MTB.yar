
rule Trojan_Win32_Glupteba_EAS_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.EAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b f3 d3 ee 03 c3 89 45 e4 03 75 dc 8b 45 e4 31 45 fc } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}