
rule Trojan_Win32_Kpot_RA_MTB{
	meta:
		description = "Trojan:Win32/Kpot.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {81 f3 07 eb dd 13 81 6c 24 90 01 01 52 ef 6f 62 2d 90 01 04 81 6c 24 90 01 01 68 19 2a 14 81 44 24 90 01 01 be 08 9a 76 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}