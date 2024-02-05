
rule Trojan_Win32_Tibs_GA{
	meta:
		description = "Trojan:Win32/Tibs.GA,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {87 02 03 55 08 03 55 0c 90 03 00 04 90 09 20 00 90 02 50 0f c8 b9 90 01 04 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}