
rule Trojan_Win32_Amadey_CCEZ_MTB{
	meta:
		description = "Trojan:Win32/Amadey.CCEZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {2b d8 81 c3 90 01 04 8b 45 90 01 01 31 18 83 45 90 01 02 83 45 90 01 02 8b 45 90 01 01 3b 45 90 01 01 0f 82 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}