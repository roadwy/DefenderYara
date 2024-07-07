
rule Trojan_Win32_Hancitor_ARA_MTB{
	meta:
		description = "Trojan:Win32/Hancitor.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 ee c1 fa 02 8b c2 c1 e8 1f 03 c2 8d 14 80 a1 90 01 04 03 d2 2b c2 8a 14 30 30 14 31 46 3b 35 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}