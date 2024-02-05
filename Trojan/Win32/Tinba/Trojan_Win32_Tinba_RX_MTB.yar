
rule Trojan_Win32_Tinba_RX_MTB{
	meta:
		description = "Trojan:Win32/Tinba.RX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {c1 c2 05 09 0d 90 01 04 13 0d 90 01 04 81 35 90 01 04 d2 00 00 00 11 0d 90 01 04 83 25 90 01 04 4f 89 06 89 0d 90 01 04 82 f1 74 83 e1 f7 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}