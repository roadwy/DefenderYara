
rule Trojan_Win32_Razy_CS_MTB{
	meta:
		description = "Trojan:Win32/Razy.CS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {ea 31 33 b9 90 02 04 81 c3 04 00 00 00 21 c9 81 ea 90 02 04 39 c3 75 e2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}