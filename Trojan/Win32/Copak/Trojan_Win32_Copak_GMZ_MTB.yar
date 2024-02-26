
rule Trojan_Win32_Copak_GMZ_MTB{
	meta:
		description = "Trojan:Win32/Copak.GMZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {01 f8 31 0b 43 39 d3 } //05 00 
		$a_01_1 = {29 fe 29 f6 8b 12 21 ff 01 fe } //00 00 
	condition:
		any of ($a_*)
 
}