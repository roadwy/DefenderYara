
rule Trojan_Win32_Remcos_RN_MTB{
	meta:
		description = "Trojan:Win32/Remcos.RN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 04 30 ff 77 90 01 01 68 90 01 04 81 04 24 90 01 04 68 90 01 04 68 90 01 04 81 04 24 90 01 04 ff d0 68 90 01 04 5a b9 90 01 04 8b 1c 0a 81 f3 90 01 04 89 1c 08 83 e9 90 01 01 7d 90 01 01 ff e0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}