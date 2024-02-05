
rule Trojan_Win32_Chapak_ARAE_MTB{
	meta:
		description = "Trojan:Win32/Chapak.ARAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {b8 cd cc cc cc f7 e1 c1 ea 03 8d 04 92 03 c0 8b d1 2b d0 8a 82 30 b4 40 00 30 04 31 41 3b cf 72 df } //00 00 
	condition:
		any of ($a_*)
 
}