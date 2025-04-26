
rule Trojan_Win32_Zegost_ARA_MTB{
	meta:
		description = "Trojan:Win32/Zegost.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 04 0a 34 5b 88 01 41 4d 75 f5 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}