
rule Trojan_Win32_Mint_GNA_MTB{
	meta:
		description = "Trojan:Win32/Mint.GNA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_01_0 = {49 81 c9 00 ff ff ff 41 8b 45 08 03 85 c8 fb ff ff 0f b6 10 33 94 8d e0 fb ff ff 8b 45 08 03 85 c8 fb ff ff 88 10 e9 } //00 00 
	condition:
		any of ($a_*)
 
}