
rule Trojan_Win32_BunituCrypt_RTU_MTB{
	meta:
		description = "Trojan:Win32/BunituCrypt.RTU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {68 5a 16 00 00 6a 00 e8 90 01 04 8b d8 a1 90 01 04 8b 00 8b 15 90 01 04 81 c2 8a a5 08 00 03 55 90 01 01 33 c2 03 d8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}