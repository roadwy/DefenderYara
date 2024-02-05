
rule Trojan_Win32_Redline_KMM_MTB{
	meta:
		description = "Trojan:Win32/Redline.KMM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {66 0f ab d0 b8 90 01 04 66 0f a3 de 8a ca 66 f7 d6 d3 c0 8d b4 15 fc fe ff ff 81 fd 90 01 04 02 c2 66 f7 c1 2d 1f 66 81 fa 82 52 32 04 37 90 00 } //01 00 
		$a_00_1 = {e9 e6 0e 0e 00 88 06 e9 2f 61 02 00 } //00 00 
	condition:
		any of ($a_*)
 
}