
rule Trojan_Win32_Redline_CCBX_MTB{
	meta:
		description = "Trojan:Win32/Redline.CCBX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 c0 33 c3 f6 2f 47 e2 } //00 00 
	condition:
		any of ($a_*)
 
}