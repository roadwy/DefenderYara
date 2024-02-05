
rule Trojan_Win32_Redline_GDJ_MTB{
	meta:
		description = "Trojan:Win32/Redline.GDJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b c6 83 e0 03 59 8a 80 90 01 04 32 c3 88 86 90 01 04 46 81 fe 90 01 04 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}