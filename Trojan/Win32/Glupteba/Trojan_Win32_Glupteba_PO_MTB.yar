
rule Trojan_Win32_Glupteba_PO_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.PO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 4d e4 33 4d f0 89 4d e4 8b 55 e4 33 55 ec 89 55 e4 8b 45 d0 2b 45 e4 89 45 d0 8b 4d e8 2b 4d d8 89 4d e8 e9 [0-04] 8b 55 08 8b 45 d0 89 02 8b 4d 08 8b 55 f4 89 51 04 8b e5 5d c2 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}