
rule Trojan_Win32_Glupteba_DEC_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.DEC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b c6 d3 e0 03 85 ?? fd ff ff 89 45 f8 8b 85 ?? fd ff ff 03 c6 c1 ee 05 03 b5 ?? fd ff ff 89 85 ?? fd ff ff 8b 85 ?? fd ff ff 31 45 f8 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}