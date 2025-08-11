
rule Trojan_Win32_Mint_AF_MTB{
	meta:
		description = "Trojan:Win32/Mint.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {66 89 8d 58 8b fa ff c6 85 4c ff ff ff 55 c6 85 4d ff ff ff 8b c6 85 4e ff ff ff ec c6 85 4f ff ff ff 8b c6 85 50 ff ff ff 55 c6 85 51 ff ff ff 08 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}