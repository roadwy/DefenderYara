
rule Trojan_Win32_Vebzenpak_GG_MTB{
	meta:
		description = "Trojan:Win32/Vebzenpak.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 0f 0f ee ca 90 02 30 89 0c 24 90 02 30 02 ca 31 34 24 90 02 20 02 ca 90 02 40 89 0c 18 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}