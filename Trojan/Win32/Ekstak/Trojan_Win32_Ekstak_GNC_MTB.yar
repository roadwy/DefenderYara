
rule Trojan_Win32_Ekstak_GNC_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.GNC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {2a 01 00 00 00 de ba 33 00 7b 19 30 00 00 da 0a 00 73 } //00 00 
	condition:
		any of ($a_*)
 
}