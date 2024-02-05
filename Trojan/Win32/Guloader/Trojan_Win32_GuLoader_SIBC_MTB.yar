
rule Trojan_Win32_GuLoader_SIBC_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.SIBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 2c 17 66 90 02 20 90 18 90 02 20 90 18 90 02 20 81 f5 90 01 04 90 02 20 90 18 90 02 20 90 18 90 02 20 01 2c 16 90 02 20 90 18 90 02 20 90 18 90 02 20 90 18 83 da 04 0f 8d 90 01 04 90 02 20 90 18 90 02 20 90 18 90 02 20 ff e6 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}