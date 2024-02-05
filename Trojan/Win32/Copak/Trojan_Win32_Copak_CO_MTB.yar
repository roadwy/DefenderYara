
rule Trojan_Win32_Copak_CO_MTB{
	meta:
		description = "Trojan:Win32/Copak.CO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {31 31 21 db 89 d8 81 c1 01 00 00 00 81 e8 01 00 00 00 bb 90 02 04 39 d1 75 d4 90 00 } //02 00 
		$a_03_1 = {31 18 81 ef 01 00 00 00 40 81 ef 90 02 04 89 f7 39 d0 75 dd 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}