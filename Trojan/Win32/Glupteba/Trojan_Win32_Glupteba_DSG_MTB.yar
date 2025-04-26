
rule Trojan_Win32_Glupteba_DSG_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.DSG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b c7 03 f7 d3 e0 89 b5 ?? ?? ff ff 8b f7 c1 ee 05 03 85 ?? ?? ff ff 03 b5 ?? ?? ff ff 89 45 ?? 8b 85 ?? ?? ff ff 31 45 ?? 81 3d ?? ?? ?? ?? 3f 0b 00 00 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}