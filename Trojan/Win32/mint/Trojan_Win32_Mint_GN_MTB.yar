
rule Trojan_Win32_Mint_GN_MTB{
	meta:
		description = "Trojan:Win32/Mint.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_01_0 = {03 f9 8b 4d f8 81 45 f8 47 86 c8 61 8b c6 c1 e8 05 03 45 e8 03 ce 33 f9 33 f8 2b df ff 4d f4 } //00 00 
	condition:
		any of ($a_*)
 
}