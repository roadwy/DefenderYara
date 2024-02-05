
rule Trojan_Win32_Amadey_AER_MTB{
	meta:
		description = "Trojan:Win32/Amadey.AER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {02 e9 97 22 ff 34 df 38 68 90 01 01 17 fd ed e4 90 01 01 8b 11 47 88 20 38 0b 11 e9 b2 61 6d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}