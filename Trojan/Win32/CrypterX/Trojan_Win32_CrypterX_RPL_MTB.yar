
rule Trojan_Win32_CrypterX_RPL_MTB{
	meta:
		description = "Trojan:Win32/CrypterX.RPL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {30 86 f2 a1 42 00 8b 45 fc 8d 88 f0 a1 42 00 b8 1f 85 eb 51 03 ce f7 e1 8b ce c1 ea 03 6b c2 19 2b c8 0f b6 81 03 68 42 00 30 86 f3 a1 42 00 } //00 00 
	condition:
		any of ($a_*)
 
}