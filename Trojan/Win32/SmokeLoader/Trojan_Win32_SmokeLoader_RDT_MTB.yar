
rule Trojan_Win32_SmokeLoader_RDT_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.RDT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b 4c 24 0c 30 04 31 83 7d 0c 0f 75 57 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_SmokeLoader_RDT_MTB_2{
	meta:
		description = "Trojan:Win32/SmokeLoader.RDT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {e8 fa fe ff ff 30 04 33 83 ff 0f 75 21 } //00 00 
	condition:
		any of ($a_*)
 
}