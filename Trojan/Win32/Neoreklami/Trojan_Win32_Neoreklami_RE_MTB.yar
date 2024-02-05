
rule Trojan_Win32_Neoreklami_RE_MTB{
	meta:
		description = "Trojan:Win32/Neoreklami.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {99 89 84 24 90 01 02 00 00 89 94 24 90 01 02 00 00 ff b4 24 90 01 02 00 00 ff b4 24 90 01 02 00 00 90 09 09 00 00 00 33 84 24 90 01 02 00 00 90 00 } //01 00 
		$a_03_1 = {d3 f8 99 89 84 24 90 01 02 00 00 89 94 24 90 01 02 00 00 ff b4 24 90 01 02 00 00 ff b4 24 90 01 02 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}