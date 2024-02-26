
rule Trojan_Win32_SmokeLoader_RDO_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.RDO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {8b c6 8b d6 c1 e0 04 c1 ea 05 03 54 24 90 01 01 03 c5 8d 0c 37 33 c1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}