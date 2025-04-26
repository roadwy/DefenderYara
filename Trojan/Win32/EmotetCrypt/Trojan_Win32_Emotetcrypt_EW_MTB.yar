
rule Trojan_Win32_Emotetcrypt_EW_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.EW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {88 14 28 8b 54 24 ?? 8b 44 24 ?? 0f b6 04 02 8b 54 24 ?? 0f b6 14 2a 03 c2 33 d2 bd ?? ?? ?? ?? f7 f5 8b 44 24 ?? 2b d3 2b 15 ?? ?? ?? ?? 2b d6 03 15 ?? ?? ?? ?? 0f b6 14 02 30 54 0f ff } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}