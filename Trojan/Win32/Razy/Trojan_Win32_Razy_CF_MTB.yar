
rule Trojan_Win32_Razy_CF_MTB{
	meta:
		description = "Trojan:Win32/Razy.CF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {31 02 81 eb 90 01 04 89 db 42 39 fa 75 de 90 00 } //02 00 
		$a_03_1 = {21 c0 40 31 31 81 c1 90 02 04 21 c3 39 d1 75 d9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}