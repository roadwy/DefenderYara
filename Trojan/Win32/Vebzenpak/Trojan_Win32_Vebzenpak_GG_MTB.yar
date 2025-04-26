
rule Trojan_Win32_Vebzenpak_GG_MTB{
	meta:
		description = "Trojan:Win32/Vebzenpak.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 0f 0f ee ca [0-30] 89 0c 24 [0-30] 02 ca 31 34 24 [0-20] 02 ca [0-40] 89 0c 18 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}