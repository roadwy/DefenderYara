
rule Trojan_Win32_Copak_SPDV_MTB{
	meta:
		description = "Trojan:Win32/Copak.SPDV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {bf d8 85 40 00 e8 ?? ?? ?? ?? b8 9b e8 34 0f be e8 17 22 f4 31 3a 89 c6 42 56 58 39 da 75 e1 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}