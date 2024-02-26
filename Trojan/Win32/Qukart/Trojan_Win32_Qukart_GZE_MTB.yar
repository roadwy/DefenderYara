
rule Trojan_Win32_Qukart_GZE_MTB{
	meta:
		description = "Trojan:Win32/Qukart.GZE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {c0 2e 64 61 90 01 02 00 00 00 f8 33 00 00 00 c0 02 00 f8 33 00 90 00 } //0a 00 
		$a_01_1 = {00 69 45 49 6a 72 6b 42 73 67 82 00 00 00 10 } //00 00 
	condition:
		any of ($a_*)
 
}