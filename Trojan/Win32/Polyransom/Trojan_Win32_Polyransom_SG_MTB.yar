
rule Trojan_Win32_Polyransom_SG_MTB{
	meta:
		description = "Trojan:Win32/Polyransom.SG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {e9 00 00 00 00 32 c2 88 07 90 01 06 83 f9 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}