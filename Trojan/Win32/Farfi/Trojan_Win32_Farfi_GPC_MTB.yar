
rule Trojan_Win32_Farfi_GPC_MTB{
	meta:
		description = "Trojan:Win32/Farfi.GPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_01_0 = {6a 00 ff d6 90 90 8a 17 6a 00 32 d3 10 da 88 17 47 ff d6 } //00 00 
	condition:
		any of ($a_*)
 
}