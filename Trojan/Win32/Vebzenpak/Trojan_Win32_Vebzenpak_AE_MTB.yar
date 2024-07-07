
rule Trojan_Win32_Vebzenpak_AE_MTB{
	meta:
		description = "Trojan:Win32/Vebzenpak.AE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f 7e d2 81 90 02 25 90 13 90 02 15 46 90 02 15 8b 17 90 02 15 0f 6e fe 90 02 15 90 18 0f 6e d2 90 02 15 0f ef d7 90 02 15 c3 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}