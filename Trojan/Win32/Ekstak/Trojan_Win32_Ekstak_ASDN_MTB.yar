
rule Trojan_Win32_Ekstak_ASDN_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASDN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {2a 01 00 00 00 d2 4a 6e 00 49 af 6a 00 00 be 90 02 04 49 b9 11 68 6a 00 00 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}