
rule Trojan_Win32_Vidar_GNA_MTB{
	meta:
		description = "Trojan:Win32/Vidar.GNA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_01_0 = {33 ed 31 54 ef 10 31 54 ef 14 45 } //00 00 
	condition:
		any of ($a_*)
 
}