
rule Trojan_Win32_Redline_GPAF_MTB{
	meta:
		description = "Trojan:Win32/Redline.GPAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {33 df 33 d8 2b f3 8b d6 c1 e2 04 } //00 00 
	condition:
		any of ($a_*)
 
}