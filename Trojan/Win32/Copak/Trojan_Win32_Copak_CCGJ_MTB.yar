
rule Trojan_Win32_Copak_CCGJ_MTB{
	meta:
		description = "Trojan:Win32/Copak.CCGJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 f1 29 f6 31 3a 09 c9 42 09 c9 01 f1 39 da 75 } //00 00 
	condition:
		any of ($a_*)
 
}