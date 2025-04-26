
rule Trojan_Win32_Glupteba_DSB_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.DSB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {bb 87 d5 7c 3a 81 45 ?? 8c eb 73 22 8b 4d ?? 8b 45 ?? 8b df d3 e3 8b 0d ?? ?? ?? ?? 8b f7 c1 ee 05 03 5d ?? 03 75 ?? 03 c7 33 d8 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}