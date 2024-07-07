
rule Trojan_Win32_Glupteba_SPDR_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.SPDR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ba d8 85 40 00 41 89 c8 e8 90 01 04 31 13 09 c1 81 c3 90 01 04 21 c0 29 c1 39 f3 75 e1 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}