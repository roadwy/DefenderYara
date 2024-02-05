
rule Trojan_Win32_Tnega_QR_MTB{
	meta:
		description = "Trojan:Win32/Tnega.QR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {81 c2 ea 5a b3 7c 31 03 b9 90 01 04 01 c9 43 39 f3 75 e2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}