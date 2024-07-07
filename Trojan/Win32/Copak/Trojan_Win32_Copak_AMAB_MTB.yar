
rule Trojan_Win32_Copak_AMAB_MTB{
	meta:
		description = "Trojan:Win32/Copak.AMAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 1a f7 d7 09 c9 81 e3 90 01 04 21 f6 f7 d7 31 18 21 c9 46 01 cf 81 c0 01 00 00 00 29 cf 89 ce 81 c1 90 01 04 42 01 c9 f7 d6 f7 d6 81 f8 90 01 04 0f 8c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}