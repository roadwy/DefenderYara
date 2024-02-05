
rule Trojan_Win32_BunituCrypt_DLL_MTB{
	meta:
		description = "Trojan:Win32/BunituCrypt.DLL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {68 4f 0c 00 00 6a 00 e8 90 01 04 03 05 90 01 04 01 05 90 01 04 a1 90 01 04 01 05 90 01 04 a1 90 01 04 01 05 90 01 04 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}