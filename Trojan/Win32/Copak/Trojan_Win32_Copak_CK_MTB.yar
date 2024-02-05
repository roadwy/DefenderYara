
rule Trojan_Win32_Copak_CK_MTB{
	meta:
		description = "Trojan:Win32/Copak.CK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {4b 09 db e8 90 02 04 31 07 81 c7 01 00 00 00 39 f7 75 e6 90 00 } //02 00 
		$a_03_1 = {31 06 81 c1 90 02 04 29 cf 46 81 e9 90 02 04 81 e9 90 02 04 39 de 75 d8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}