
rule Trojan_Win32_Pramro_B{
	meta:
		description = "Trojan:Win32/Pramro.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {f7 f9 81 c2 9b 04 00 00 89 95 90 01 02 ff ff 66 8b 95 90 01 02 ff ff 52 ff 15 90 09 06 00 99 b9 90 03 02 02 10 27 40 1f 00 00 90 00 } //02 00 
		$a_03_1 = {c7 85 d4 ef ff ff f4 01 00 00 0f be 90 01 01 d1 df ff ff 83 90 01 01 02 89 90 01 01 d0 ef ff ff eb 05 e9 90 00 } //01 00 
		$a_01_2 = {4e 45 54 53 44 } //00 00  NETSD
	condition:
		any of ($a_*)
 
}