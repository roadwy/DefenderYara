
rule Trojan_Win32_Ekstak_ASEU_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASEU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {8d 54 24 10 8b d8 52 55 ff 15 90 01 03 00 68 90 01 03 00 53 8b e8 ff 15 90 01 03 00 3b ef 89 86 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}