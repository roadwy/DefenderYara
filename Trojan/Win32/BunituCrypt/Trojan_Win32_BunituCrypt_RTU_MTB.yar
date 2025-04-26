
rule Trojan_Win32_BunituCrypt_RTU_MTB{
	meta:
		description = "Trojan:Win32/BunituCrypt.RTU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {68 5a 16 00 00 6a 00 e8 ?? ?? ?? ?? 8b d8 a1 ?? ?? ?? ?? 8b 00 8b 15 ?? ?? ?? ?? 81 c2 8a a5 08 00 03 55 ?? 33 c2 03 d8 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}