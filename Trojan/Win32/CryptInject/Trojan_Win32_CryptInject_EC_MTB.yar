
rule Trojan_Win32_CryptInject_EC_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 e0 01 85 c0 74 ?? 8a 45 ?? 30 45 ?? 8a 45 ?? 83 e0 ?? 88 45 ?? d0 65 ?? 80 7d ?? ?? 74 ?? 80 75 ?? ?? d0 6d ?? ff 45 ?? 83 7d ?? ?? 7e } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}