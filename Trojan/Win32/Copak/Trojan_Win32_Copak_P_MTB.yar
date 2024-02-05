
rule Trojan_Win32_Copak_P_MTB{
	meta:
		description = "Trojan:Win32/Copak.P!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {01 d6 81 ea 90 01 04 4e bf 90 01 04 29 f2 e8 90 01 04 31 38 81 c0 90 01 04 39 c8 75 e8 29 d2 81 ee 90 01 04 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}