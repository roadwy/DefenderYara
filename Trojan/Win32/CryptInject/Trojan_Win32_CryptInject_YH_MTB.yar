
rule Trojan_Win32_CryptInject_YH_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.YH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {56 8b f2 33 c0 57 8b f9 85 f6 7e 1d 0f 1f 40 00 8a 0c 38 8b d0 83 e2 ?? 80 e9 ?? 32 8a ?? ?? ?? ?? 88 0c 38 40 3b c6 7c e7 5f 5e c3 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}