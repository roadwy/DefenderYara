
rule Trojan_Win32_Cridex_DEA_MTB{
	meta:
		description = "Trojan:Win32/Cridex.DEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b ef 2b e8 8d 44 2a a5 81 fa 90 01 04 90 13 81 c3 90 01 04 8d 44 0a fa 8b 15 90 01 04 89 1d 90 01 04 89 9c 32 90 01 04 8b 1d 90 01 04 8d 0c c3 03 c8 83 c6 04 89 0d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}