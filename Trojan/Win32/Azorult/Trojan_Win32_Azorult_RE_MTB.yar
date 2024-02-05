
rule Trojan_Win32_Azorult_RE_MTB{
	meta:
		description = "Trojan:Win32/Azorult.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b ec 83 e4 f8 b8 78 41 00 00 e8 90 01 04 81 3d 90 01 04 77 01 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}