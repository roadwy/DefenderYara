
rule Trojan_Win32_CryptInject_YZ_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.YZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {30 04 31 41 3b cf 72 ?? 68 ?? ?? ?? 00 6a 40 ?? ?? ff 15 ?? ?? ?? 00 8b 4d f4 8b 55 f8 8a 45 ff 30 02 42 e2 ?? ff ?? ?? e8 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}