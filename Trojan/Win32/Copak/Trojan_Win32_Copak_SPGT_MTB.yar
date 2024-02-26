
rule Trojan_Win32_Copak_SPGT_MTB{
	meta:
		description = "Trojan:Win32/Copak.SPGT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_03_0 = {8b 1c 24 83 c4 04 29 c9 e8 90 01 04 29 cf 31 1a 81 ef 90 01 04 4f 81 c2 01 00 00 00 01 c9 21 cf 39 f2 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}