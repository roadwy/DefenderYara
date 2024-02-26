
rule Trojan_Win32_Qukart_SPXX_MTB{
	meta:
		description = "Trojan:Win32/Qukart.SPXX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_01_0 = {89 da 21 d2 81 e0 ff 00 00 00 29 cb 21 c9 81 c3 34 74 06 72 31 06 42 f7 d2 46 b9 2e 19 2a 9e 81 c2 09 75 f6 08 21 cb 47 21 d1 81 ea 85 77 6c ab 81 fe } //00 00 
	condition:
		any of ($a_*)
 
}