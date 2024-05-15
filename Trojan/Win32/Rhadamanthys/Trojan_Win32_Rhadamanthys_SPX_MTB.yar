
rule Trojan_Win32_Rhadamanthys_SPX_MTB{
	meta:
		description = "Trojan:Win32/Rhadamanthys.SPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {33 c8 c7 05 90 01 04 ee 3d ea f4 8b 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}