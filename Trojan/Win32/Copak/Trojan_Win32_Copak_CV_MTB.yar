
rule Trojan_Win32_Copak_CV_MTB{
	meta:
		description = "Trojan:Win32/Copak.CV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {31 39 43 81 c1 04 00 00 00 81 c3 01 00 00 00 39 d1 75 e8 } //02 00 
		$a_01_1 = {31 1e 68 3a 04 3c c2 8b 3c 24 83 c4 04 81 ef 01 00 00 00 81 c6 04 00 00 00 09 c0 39 d6 75 dc } //00 00 
	condition:
		any of ($a_*)
 
}