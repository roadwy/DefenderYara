
rule Trojan_Win32_Cridex_DAE_MTB{
	meta:
		description = "Trojan:Win32/Cridex.DAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 5c 24 10 0f b7 eb 81 c7 90 01 04 8b c6 2b c5 89 3a 83 c2 04 83 e8 53 83 6c 24 18 01 89 54 24 14 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}