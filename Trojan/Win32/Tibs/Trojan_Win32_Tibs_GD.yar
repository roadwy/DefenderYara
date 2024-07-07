
rule Trojan_Win32_Tibs_GD{
	meta:
		description = "Trojan:Win32/Tibs.GD,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {87 02 2b 55 08 2b 55 0c 90 03 00 04 90 09 24 00 90 02 44 0f c8 b9 90 01 04 eb 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}