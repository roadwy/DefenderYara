
rule Trojan_Win32_Virut_AVI_MTB{
	meta:
		description = "Trojan:Win32/Virut.AVI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 b7 6f c5 20 ba 2b e1 8d 1b fa 85 ee 1f 53 ef 34 a2 cf 56 } //00 00 
	condition:
		any of ($a_*)
 
}