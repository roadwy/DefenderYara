
rule Trojan_Win32_RedLine_DX_MTB{
	meta:
		description = "Trojan:Win32/RedLine.DX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 44 24 10 89 6c 24 10 8d 6c 24 10 2b e0 53 56 57 a1 04 73 4d 00 31 45 fc 33 c5 50 89 65 e8 ff 75 f8 8b 45 fc c7 45 fc fe ff ff ff 89 45 f8 8d 45 f0 64 a3 } //00 00 
	condition:
		any of ($a_*)
 
}