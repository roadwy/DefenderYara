
rule Trojan_Win32_Copak_GNB_MTB{
	meta:
		description = "Trojan:Win32/Copak.GNB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 d2 09 d2 e8 90 01 04 42 81 c1 90 01 04 31 07 47 89 d2 21 c9 39 df 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}