
rule Trojan_Win32_Razy_VN_MTB{
	meta:
		description = "Trojan:Win32/Razy.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {64 95 71 67 68 90 01 04 58 4f 81 e9 90 01 04 e8 90 01 04 31 06 81 c6 90 01 04 89 c9 39 de 75 e0 68 90 01 04 5f c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}