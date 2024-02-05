
rule Trojan_Win32_Fragtor_KAB_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.KAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {09 cb 8b 3e 81 c0 90 01 04 09 db 81 e7 90 01 04 21 cb 81 e8 90 01 04 31 3a 01 db 89 d8 42 01 cb 09 c3 81 c6 90 01 04 48 09 db 81 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}