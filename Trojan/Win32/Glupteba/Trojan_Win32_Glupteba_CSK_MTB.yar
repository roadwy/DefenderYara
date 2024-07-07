
rule Trojan_Win32_Glupteba_CSK_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.CSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {81 f3 07 eb dd 13 81 ad 90 01 04 52 ef 6f 62 b8 90 01 04 81 ad 90 01 04 68 19 2a 14 81 85 90 01 04 be 08 9a 76 8b 8d 90 01 04 8b d7 d3 e2 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}