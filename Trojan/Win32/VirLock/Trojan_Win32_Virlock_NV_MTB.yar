
rule Trojan_Win32_Virlock_NV_MTB{
	meta:
		description = "Trojan:Win32/Virlock.NV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {e9 cb e3 ff ff ff d1 43 c1 c6 90 01 01 33 f7 8b d6 e9 fe 02 00 00 68 90 01 04 c1 e7 1a 03 da 87 f7 81 c2 90 01 04 03 f7 03 df 90 00 } //03 00 
		$a_03_1 = {8b fe 33 df 47 2b fb 81 ca 90 01 04 f7 da 2b d6 81 f2 90 01 04 c1 ef 10 c1 ca 90 01 01 c1 ee 14 e9 6c 01 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}