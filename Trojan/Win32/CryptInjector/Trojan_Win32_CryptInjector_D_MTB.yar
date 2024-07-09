
rule Trojan_Win32_CryptInjector_D_MTB{
	meta:
		description = "Trojan:Win32/CryptInjector.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 7d f4 00 76 30 8b 45 f4 83 e0 03 85 c0 75 15 8b 45 f4 8a 80 ?? ?? ?? ?? 34 ?? 8b 55 fc 03 55 f4 88 02 eb 11 8b 45 f4 8a 80 ?? ?? ?? ?? 8b 55 fc 03 55 f4 88 02 ff 45 f4 81 7d f4 ?? ?? ?? ?? 75 be } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}