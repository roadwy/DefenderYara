
rule Trojan_Win32_Razy_CO_MTB{
	meta:
		description = "Trojan:Win32/Razy.CO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {31 30 89 db 29 da 81 c0 04 00 00 00 39 c8 75 eb } //02 00 
		$a_01_1 = {31 1e 4f 46 09 c7 57 8b 04 24 83 c4 04 39 d6 75 e3 } //00 00 
	condition:
		any of ($a_*)
 
}