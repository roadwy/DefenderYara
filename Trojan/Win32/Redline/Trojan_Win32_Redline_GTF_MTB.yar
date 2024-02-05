
rule Trojan_Win32_Redline_GTF_MTB{
	meta:
		description = "Trojan:Win32/Redline.GTF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {33 d2 8b c6 f7 75 10 83 c4 0c 8a 82 90 01 04 30 04 37 46 3b 75 08 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}