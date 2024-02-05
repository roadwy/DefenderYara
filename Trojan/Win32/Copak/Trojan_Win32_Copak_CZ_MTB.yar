
rule Trojan_Win32_Copak_CZ_MTB{
	meta:
		description = "Trojan:Win32/Copak.CZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {39 f6 74 01 ea 31 16 81 c6 04 00 00 00 39 fe 75 ef } //02 00 
		$a_01_1 = {31 0e 21 ff 81 c6 04 00 00 00 39 de 75 ed } //00 00 
	condition:
		any of ($a_*)
 
}