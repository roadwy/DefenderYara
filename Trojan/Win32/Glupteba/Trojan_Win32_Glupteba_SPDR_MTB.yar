
rule Trojan_Win32_Glupteba_SPDR_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.SPDR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ba d8 85 40 00 41 89 c8 e8 ?? ?? ?? ?? 31 13 09 c1 81 c3 ?? ?? ?? ?? 21 c0 29 c1 39 f3 75 e1 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}