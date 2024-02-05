
rule Trojan_Win32_SmokeLoader_RDL_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.RDL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {03 7d d8 8b 45 e4 31 45 fc 33 7d fc } //00 00 
	condition:
		any of ($a_*)
 
}