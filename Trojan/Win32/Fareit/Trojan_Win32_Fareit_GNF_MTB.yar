
rule Trojan_Win32_Fareit_GNF_MTB{
	meta:
		description = "Trojan:Win32/Fareit.GNF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {02 00 80 f6 38 02 00 07 02 00 80 74 02 00 80 90 01 02 00 80 90 01 04 1a 39 02 00 97 02 00 80 32 39 02 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}