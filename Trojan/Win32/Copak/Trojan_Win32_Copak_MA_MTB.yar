
rule Trojan_Win32_Copak_MA_MTB{
	meta:
		description = "Trojan:Win32/Copak.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {81 c1 01 00 00 00 01 f9 01 c9 b8 d8 85 40 00 e8 19 00 00 00 31 06 81 c7 01 00 00 00 49 46 21 cf 39 de 75 e6 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}