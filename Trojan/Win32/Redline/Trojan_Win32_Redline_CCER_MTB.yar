
rule Trojan_Win32_Redline_CCER_MTB{
	meta:
		description = "Trojan:Win32/Redline.CCER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 c8 0f be 06 33 c1 69 c0 90 01 04 33 f8 8b 6c 24 90 01 01 8b c7 c1 e8 90 01 01 33 c7 69 c0 90 01 04 8b c8 c1 e9 0f 33 c8 74 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}