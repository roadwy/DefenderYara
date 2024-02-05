
rule Trojan_Win32_Copak_CM_MTB{
	meta:
		description = "Trojan:Win32/Copak.CM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {09 d3 31 0f 4a 89 d3 47 09 da 39 f7 75 e3 } //02 00 
		$a_03_1 = {8b 0c 24 83 c4 04 e8 90 02 04 31 0f 4a 81 c7 01 00 00 00 39 f7 75 de 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}