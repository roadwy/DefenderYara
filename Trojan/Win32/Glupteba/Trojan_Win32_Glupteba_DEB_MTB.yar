
rule Trojan_Win32_Glupteba_DEB_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.DEB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 4d f4 8b bd ?? fd ff ff 8b d8 d3 e3 8b 8d ?? fd ff ff c1 ef 05 03 bd ?? fd ff ff 03 9d ?? fd ff ff 03 c8 33 d9 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}