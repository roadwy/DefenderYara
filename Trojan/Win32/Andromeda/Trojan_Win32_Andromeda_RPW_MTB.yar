
rule Trojan_Win32_Andromeda_RPW_MTB{
	meta:
		description = "Trojan:Win32/Andromeda.RPW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {c6 85 e0 fe ff ff 4d c6 85 e1 fe ff ff 65 c6 85 e2 fe ff ff 73 c6 85 e3 fe ff ff 73 c6 85 e4 fe ff ff 61 c6 85 e5 fe ff ff 67 c6 85 e6 fe ff ff 65 c6 85 e7 fe ff ff 42 c6 85 e8 fe ff ff 6f c6 85 e9 fe ff ff 78 c6 85 ea fe ff ff 41 c6 85 eb fe ff ff 00 8d 95 d8 fe ff ff 52 ff 95 20 ff ff ff 89 85 30 ff ff ff 8d 85 e0 fe ff ff 50 8b 8d 30 ff ff ff 51 ff 95 24 ff ff ff } //00 00 
	condition:
		any of ($a_*)
 
}